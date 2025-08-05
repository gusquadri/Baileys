/* @ts-ignore */
import * as libsignal from 'libsignal'
import type { SignalAuthState, SignalKeyStoreWithTransaction } from '../Types'
import type { SignalRepository } from '../Types/Signal'
import { generateSignalPubKey } from '../Utils'
import { jidDecode, jidEncode } from '../WABinary'
import { LIDMappingStore } from '../Utils/lid-mapping'
import type { SenderKeyStore } from './Group/group_cipher'
import { SenderKeyName } from './Group/sender-key-name'
import { SenderKeyRecord } from './Group/sender-key-record'
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage } from './Group'
import type { StorageType } from 'libsignal'

export function makeLibSignalRepository(auth: SignalAuthState): SignalRepository {
	const storage : StorageType & SenderKeyStore = signalStorage(auth)
	const lidMapping = new LIDMappingStore(auth.keys as SignalKeyStoreWithTransaction)
	
	/**
	 * Migrate session from one address to another (for LID/PN compatibility)
	 */
	const migrateSession = async (fromJid: string, toJid: string): Promise<void> => {
		const fromAddr = jidToSignalProtocolAddress(fromJid)
		const toAddr = jidToSignalProtocolAddress(toJid)
		
		const fromAddrStr = fromAddr.toString()
		const toAddrStr = toAddr.toString()
		
		if (fromAddrStr === toAddrStr) {
			return // No migration needed
		}
		
		try {
			// Load session from source address
			const fromSession = await storage.loadSession(fromAddrStr)
			if (fromSession && fromSession.haveOpenSession()) {
				// Check if destination already has a session
				const toSession = await storage.loadSession(toAddrStr)
				if (!toSession || !toSession.haveOpenSession()) {
					// Copy session to destination address
					await storage.storeSession(toAddrStr, fromSession)
					console.log(`Migrated session from ${fromJid} to ${toJid}`)
				}
			}
		} catch (error) {
			console.error(`Failed to migrate session from ${fromJid} to ${toJid}:`, error)
		}
	}

	/**
	 * Find and migrate LID sessions for decryption
	 */
	const findSessionForDecryption = async (jid: string): Promise<string> => {
		const addr = jidToSignalProtocolAddress(jid)
		const addrStr = addr.toString()
		
		// First try the provided JID
		const existingSession = await storage.loadSession(addrStr)
		if (existingSession && existingSession.haveOpenSession()) {
			return jid
		}
		
		// Check if this is our own device - skip LID mapping for performance
		// Note: auth.creds here is SignalCreds, but we need to get the full AuthenticationCreds
		// For now, we'll check if the auth object has the me property through type assertion
		const authCreds = (auth as any).creds || auth
		const ownPhoneNumber = authCreds.me?.id?.split('@')[0]?.split(':')[0]
		const incomingUser = jidDecode(jid)?.user
		
		if (ownPhoneNumber && incomingUser === ownPhoneNumber) {
			console.log(`⚡ Fast path: Own device detected (${jid}), skipping LID lookup`)
			return jid // Return original JID - no LID mapping needed for own devices
		}
		
		// If it's a phone number (and not our own), check for LID mapping
		if (LIDMappingStore.isPN(jid)) {
			// Extract device ID from original JID to preserve it
			const decoded = jidDecode(jid)
			const device = decoded?.device
			
			// Use base JID (without device) for LID mapping lookup
			const baseJid = jidEncode(decoded!.user, 's.whatsapp.net')
			console.log(`🔍 LID mapping lookup for external contact: ${baseJid}`)
			
			const lidForPN = await lidMapping.getLIDForPN(baseJid)
			if (lidForPN) {
				// Reconstruct LID with same device ID
				const lidDecoded = jidDecode(lidForPN)
				let lidWithDevice = lidForPN
				
				// If original JID had a device ID, apply it to LID
				if (device && lidDecoded) {
					lidWithDevice = jidEncode(lidDecoded.user, 'lid', device)
				}
				
				console.log(`✅ Found LID mapping: ${baseJid} → ${lidWithDevice}`)
				
				const lidAddr = jidToSignalProtocolAddress(lidWithDevice)
				const lidSession = await storage.loadSession(lidAddr.toString())
				if (lidSession && lidSession.haveOpenSession()) {
					// Migrate session from LID to PN for future use
					await migrateSession(lidWithDevice, jid)
					return lidWithDevice // Use LID for this decryption
				}
			} else {
				console.log(`❌ No LID mapping found for: ${baseJid}`)
			}
		}
		
		// If it's a LID, check for PN mapping
		if (LIDMappingStore.isLID(jid)) {
			// Extract device ID from original JID to preserve it
			const decoded = jidDecode(jid)
			const device = decoded?.device
			
			// Use base JID (without device) for PN mapping lookup
			const baseJid = jidEncode(decoded!.user, 'lid')
			const pnForLID = await lidMapping.getPNForLID(baseJid)
			if (pnForLID) {
				// Reconstruct PN with same device ID
				const pnDecoded = jidDecode(pnForLID)
				let pnWithDevice = pnForLID
				
				// If original JID had a device ID, apply it to PN
				if (device && pnDecoded) {
					pnWithDevice = jidEncode(pnDecoded.user, 's.whatsapp.net', device)
				}
				
				const pnAddr = jidToSignalProtocolAddress(pnWithDevice)
				const pnSession = await storage.loadSession(pnAddr.toString())
				if (pnSession && pnSession.haveOpenSession()) {
					// Migrate session from PN to LID for future use
					await migrateSession(pnWithDevice, jid)
					return pnWithDevice // Use PN for this decryption
				}
			}
		}
		
		// No session found, return original JID
		return jid
	}

	return {
		decryptGroupMessage({ group, authorJid, msg }) {
			const senderName = jidToSignalSenderKeyName(group, authorJid)
			const cipher = new GroupCipher(storage, senderName)

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				return cipher.decrypt(msg)
			})
		},

		async processSenderKeyDistributionMessage({ item, authorJid }) {
			const builder = new GroupSessionBuilder(storage)
			if (!item.groupId) {
				throw new Error('Group ID is required for sender key distribution message')
			}

			const senderName = jidToSignalSenderKeyName(item.groupId, authorJid)

			const senderMsg = new SenderKeyDistributionMessage(
				null,
				null,
				null,
				null,
				item.axolotlSenderKeyDistributionMessage
			)
			const senderNameStr = senderName.toString()

			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr])
				if (!senderKey) {
					await storage.storeSenderKey(senderName, new SenderKeyRecord())
				}

				await builder.process(senderName, senderMsg)
			})
		},
		async decryptMessage({ jid, type, ciphertext }) {
			// Find the correct JID/session for decryption (handles LID/PN migration)
			const decryptionJid = await findSessionForDecryption(jid)
			const addr = jidToSignalProtocolAddress(decryptionJid)
			const session = new libsignal.SessionCipher(storage, addr)

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				let result: Buffer
				switch (type) {
					case 'pkmsg':
						result = await session.decryptPreKeyWhisperMessage(ciphertext)
						break
					case 'msg':
						result = await session.decryptWhisperMessage(ciphertext)
						break
				default:
					throw new Error(`Unknown message type: ${type}`)
				}

				return result
			})
		},
		async encryptMessage({ jid, data }) {
			// Check if we have a LID for this phone number (auto-use LID for privacy)
			let encryptionJid = jid
			
			// Skip LID lookup for our own devices (performance optimization)
			const authCreds = (auth as any).creds || auth
			const ownPhoneNumber = authCreds.me?.id?.split('@')[0]?.split(':')[0]
			const targetUser = jidDecode(jid)?.user
			
			if (LIDMappingStore.isPN(jid) && ownPhoneNumber !== targetUser) {
				// Extract device ID to preserve it
				const decoded = jidDecode(jid)
				const device = decoded?.device
				
				// Use base JID (without device) for LID mapping lookup
				const baseJid = jidEncode(decoded!.user, 's.whatsapp.net')
				console.log(`🔍 Encryption LID lookup for external contact: ${baseJid}`)
				
				const lidForPN = await lidMapping.getLIDForPN(baseJid)
				if (lidForPN) {
					// Reconstruct LID with same device ID
					const lidDecoded = jidDecode(lidForPN)
					let lidWithDevice = lidForPN
					
					// If original JID had a device ID, apply it to LID
					if (device && lidDecoded) {
						lidWithDevice = jidEncode(lidDecoded.user, 'lid', device)
					}
					
					console.log(`✅ Using LID for encryption: ${jid} → ${lidWithDevice}`)
					
					// Migrate session from PN to LID if needed
					await migrateSession(jid, lidWithDevice)
					encryptionJid = lidWithDevice
				}
			} else if (ownPhoneNumber === targetUser) {
				console.log(`⚡ Fast path: Encrypting to own device (${jid}), using direct session`)
			}
			
			const addr = jidToSignalProtocolAddress(encryptionJid)
			const cipher = new libsignal.SessionCipher(storage, addr)

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { type: sigType, body } = await cipher.encrypt(data)
				const type = sigType === 3 ? 'pkmsg' : 'msg'
				return { type, ciphertext: Buffer.from(body as any, 'binary') }
			})
		},
		async encryptGroupMessage({ group, meId, data }) {
			const senderName = jidToSignalSenderKeyName(group, meId)
			const builder = new GroupSessionBuilder(storage)

			const senderNameStr = senderName.toString()

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr])
				if (!senderKey) {
					await storage.storeSenderKey(senderName, new SenderKeyRecord())
				}

				const senderKeyDistributionMessage = await builder.create(senderName)
				const session = new GroupCipher(storage, senderName)
				const ciphertext = await session.encrypt(data)

				return {
					ciphertext,
					senderKeyDistributionMessage: senderKeyDistributionMessage.serialize()
				}
			})
		},
		async injectE2ESession({ jid, session }) {
			const cipher = new libsignal.SessionBuilder(storage, jidToSignalProtocolAddress(jid))
			const transformedSession: any = {
				registrationId: session.registrationId,
				identityKey: Buffer.from(session.identityKey),
				signedPreKey: {
					keyId: session.signedPreKey.keyId,
					keyPair: {
						pubKey: Buffer.from(session.signedPreKey.publicKey),
						privKey: Buffer.alloc(32) // Dummy private key, not needed for outgoing
					},
					signature: session.signedPreKey.signature
				}
			}

			// Add preKey only if it exists (optional for existing sessions)
			if (session.preKey) {
				transformedSession.preKey = {
					keyId: session.preKey.keyId,
					keyPair: {
						pubKey: Buffer.from(session.preKey.publicKey),
						privKey: Buffer.alloc(32) // Dummy private key, not needed for outgoing
					}
				}
			}

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				await cipher.initOutgoing(transformedSession)
			})
		},
		jidToSignalProtocolAddress(jid) {
			return jidToSignalProtocolAddress(jid).toString()
		},
		/**
		 * Store LID-PN mapping (for compatibility with whatsmeow pattern)
		 */
		async storeLIDPNMapping(lid: string, pn: string) {
			await lidMapping.storeLIDPNMapping(lid, pn)
		},
		/**
		 * Get LID mapping store instance
		 */
		getLIDMappingStore() {
			return lidMapping
		}
	}
}

const jidToSignalProtocolAddress = (jid: string) => {
	const decoded = jidDecode(jid)!
	const { user, device, server } = decoded
	
	// Handle LID addresses by appending _1
	let signalUser = user
	if (server === 'lid') {
		signalUser = `${user}_1`
	}
	
	return new libsignal.ProtocolAddress(signalUser, device || 0)
}

const jidToSignalSenderKeyName = (group: string, user: string): SenderKeyName => {
	return new SenderKeyName(group, jidToSignalProtocolAddress(user))
}

function signalStorage({ creds, keys }: SignalAuthState): StorageType & SenderKeyStore & Record<string, any> {
	return {
		loadSession: async (id: string) => {
			try {
				const { [id]: sess } = await keys.get('session', [id])
				if (sess) {
					return libsignal.SessionRecord.deserialize(sess)
				}
			} catch (e) {
				console.error('Failed to load session:', e)
				return null
			}
			return null
		},
		// TODO: Replace with libsignal.SessionRecord when type exports are added to libsignal
		storeSession: async (id: string, session: any) => {
			await keys.set({ session: { [id]: session.serialize() } })
		},
		isTrustedIdentity: async (_address: string, _identityKey: Buffer) => {
			return true
		},
		loadPreKey: async (keyId: number) => {
			const keyIdStr = keyId.toString()
			const { [keyIdStr]: key } = await keys.get('pre-key', [keyIdStr])
			if (key) {
				return {
					keyId,
					keyPair: {
						privKey: Buffer.from(key.private),
						pubKey: Buffer.from(key.public)
					}
				}
			}
			return null
		},
		removePreKey: async (keyId: number) => {
			return keys.set({ 'pre-key': { [keyId]: null } })
		},
		loadSignedPreKey: async () => {
			const key = creds.signedPreKey
			return {
				privKey: Buffer.from(key.keyPair.private),
				pubKey: Buffer.from(key.keyPair.public)
			}
		},
		loadSenderKey: async (senderKeyName: SenderKeyName) => {
			const keyId = senderKeyName.toString()
			const { [keyId]: key } = await keys.get('sender-key', [keyId])
			if (key) {
				return SenderKeyRecord.deserialize(key)
			}

			return new SenderKeyRecord()
		},
		storeSenderKey: async (senderKeyName: SenderKeyName, key: SenderKeyRecord) => {
			const keyId = senderKeyName.toString()
			const serialized = JSON.stringify(key.serialize())
			await keys.set({ 'sender-key': { [keyId]: Buffer.from(serialized, 'utf-8') } })
		},
		getOurRegistrationId: async () => creds.registrationId,
		getOurIdentity: async () => {
			const { signedIdentityKey } = creds
			return {
				privKey: Buffer.from(signedIdentityKey.private),
				pubKey: Buffer.from(generateSignalPubKey(signedIdentityKey.public))
			}
		},
		storeSignedPreKey: async (keyId: number, keyPair: any) => {
			// Store signed pre key - not implemented in current system
			console.warn('storeSignedPreKey not implemented:', keyId, keyPair)
		},
		removeSignedPreKey: async (keyId: number) => {
			// Remove signed pre key - not implemented in current system
			console.warn('removeSignedPreKey not implemented:', keyId)
		}
	}
}