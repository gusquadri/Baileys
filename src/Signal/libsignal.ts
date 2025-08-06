/* @ts-ignore */
import * as libsignal from 'libsignal'
import type { SignalAuthState, SignalKeyStoreWithTransaction } from '../Types'
import type { SignalRepository } from '../Types/Signal'
import { generateSignalPubKey } from '../Utils'
import { jidDecode } from '../WABinary'
import { LIDMappingStore } from '../Utils/lid-mapping'
import { PrivacyTokenManager } from './privacy-tokens'
import type { SenderKeyStore } from './Group/group_cipher'
import { SenderKeyName } from './Group/sender-key-name'
import { SenderKeyRecord } from './Group/sender-key-record'
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage } from './Group'
import type { StorageType } from 'libsignal'

export function makeLibSignalRepository(auth: SignalAuthState): SignalRepository {
	const lidMapping = new LIDMappingStore(auth.keys as SignalKeyStoreWithTransaction)
	const storage : StorageType & SenderKeyStore = signalStorage(auth)
	
	// Initialize privacy token manager for session migration (following whatsmeow approach)
	const privacyTokenManager = new PrivacyTokenManager(auth.keys as SignalKeyStoreWithTransaction, lidMapping)
	
	// Link managers for cross-referencing (avoiding circular dependency)
	lidMapping.setPrivacyTokenManager(privacyTokenManager)
	
	/**
	 * Server-coordinated session migration - migrate only when server notifies
	 * Based on actual WhatsApp/whatsmeow approach (NOT reactive)
	 */
	const coordinatedSessionMigration = async (fromJid: string, toJid: string): Promise<void> => {
		// WHATSAPP'S PROPER MIGRATION: Only called when server sends migration notification
		// This prevents reactive migration during message processing that causes Bad MAC
		
		console.log(`🔄 Server-coordinated migration: ${fromJid} → ${toJid}`)
		
		const fromAddr = jidToSignalProtocolAddress(fromJid)
		const toAddr = jidToSignalProtocolAddress(toJid)
		
		try {
			// 1. Load existing session from old address
			const fromSession = await storage.loadSession(fromAddr.toString())
			if (!fromSession || !fromSession.haveOpenSession()) {
				console.log(`⚠️ No active session found at ${fromJid} - skipping migration`)
				return
			}
			
			// 2. ATOMIC MIGRATION: Copy complete session state
			await storage.storeSession(toAddr.toString(), fromSession)
			
			// 3. Migrate privacy tokens
			try {
				await privacyTokenManager.migratePrivacyToken(fromJid, toJid)
				console.log(`🔐 Privacy token migrated: ${fromJid} → ${toJid}`)
			} catch (tokenError) {
				console.warn(`⚠️ Privacy token migration failed: ${fromJid} → ${toJid}`, tokenError)
			}
			
			// 4. Update LID mapping
			await lidMapping.storeLIDPNMapping(toJid, fromJid)
			
			// 5. Invalidate old session (optional - WhatsApp keeps both temporarily)
			// await storage.storeSession(fromAddr.toString(), null)
			
			console.log(`✅ Coordinated migration completed: ${fromJid} → ${toJid}`)
		} catch (error) {
			console.error(`❌ Failed coordinated migration: ${fromJid} → ${toJid}`, error)
			throw error
		}
	}

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
			// Check if destination already has a session - if yes, no migration needed
			const toSession = await storage.loadSession(toAddrStr)
			if (toSession && toSession.haveOpenSession()) {
				console.log(`Session already exists at ${toJid}, skipping migration`)
				return
			}
			
			// Load session from source address
			const fromSession = await storage.loadSession(fromAddrStr)
			if (fromSession && fromSession.haveOpenSession()) {
				// Copy session to destination address
				// NOTE: This is different from whatsmeow which likely just remaps storage keys
				// But necessary for our implementation since we can't directly remap Redis keys
				await storage.storeSession(toAddrStr, fromSession)
				console.log(`Migrated session from ${fromJid} to ${toJid}`)
			}
		} catch (error) {
			console.error(`Failed to migrate session from ${fromJid} to ${toJid}:`, error)
		}
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
			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const addr = jidToSignalProtocolAddress(jid)
				const session = new libsignal.SessionCipher(storage, addr)
				
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
			// WHATSMEOW EXACT LOGIC: Always prefer LID when available
			let encryptionJid = jid
			
			// OWN DEVICE OPTIMIZATION: Skip LID lookup for our own devices to prevent session corruption
			const authCreds = (auth as any).creds || auth
			const ownPhoneNumber = authCreds.me?.id?.split('@')[0]?.split(':')[0]
			const targetUser = jidDecode(jid)?.user
			
			if (ownPhoneNumber && targetUser === ownPhoneNumber) {
				console.log(`⚡ Own device optimization: Skipping LID lookup for ${jid} (own device)`)
				// Use the provided address directly - don't convert to LID
				encryptionJid = jid
			} else if (LIDMappingStore.isPN(jid)) {
				// whatsmeow send.go:996 - Always try to get LID for PN (external contacts only)
				try {
					const lidForPN = await lidMapping.getLIDForPN(jid)
					if (lidForPN) {
						console.log(`🔄 whatsmeow pattern: Found LID for PN: ${jid} → ${lidForPN}`)
						encryptionJid = lidForPN
						// Proactive migration (whatsmeow pattern)
						await migrateSession(jid, lidForPN)
					}
				} catch (error) {
					console.warn(`⚠️ LID lookup failed for ${jid}, using PN`)
				}
			}
			
			console.log(`📤 Final encryption identity: ${encryptionJid}`)
			
			const addr = jidToSignalProtocolAddress(encryptionJid)
			
			// Use transaction to ensure atomicity (Baileys pattern)
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				// SESSION VALIDATION: Check session health before encryption
				const targetSession = await storage.loadSession(addr.toString())
				
				if (!targetSession || !targetSession.haveOpenSession()) {
					console.log(`⚠️ No active session at ${encryptionJid}`)
					
					// BAILEYS FALLBACK PATTERN: Look for alternate session only if needed
					if (encryptionJid !== jid) {
						// We changed addresses, check if original has session
						const origAddr = jidToSignalProtocolAddress(jid)
						const origSession = await storage.loadSession(origAddr.toString())
						
						if (origSession && origSession.haveOpenSession()) {
							console.log(`✅ Found session at original address, migrating: ${jid} → ${encryptionJid}`)
							await migrateSession(jid, encryptionJid)
						}
					}
				} else {
					// Session exists - validate it's not corrupted
					console.log(`✅ Active session found for ${encryptionJid}`)
					
					// Additional validation: check if session has proper sessions data
					try {
						const sessions = (targetSession as any).sessions
						if (!sessions || sessions.length === 0) {
							console.warn(`⚠️ Session missing session data for ${encryptionJid}`)
						}
					} catch (validationError) {
						console.warn(`⚠️ Session validation failed for ${encryptionJid}:`, validationError)
					}
				}
				
				// Create cipher and attempt encryption
				const cipher = new libsignal.SessionCipher(storage, addr)
				
				try {
					const { type: sigType, body } = await cipher.encrypt(data)
					const type = sigType === 3 ? 'pkmsg' : 'msg'
					return { type, ciphertext: Buffer.from(body as any, 'binary') }
				} catch (encryptionError: any) {
					console.error(`❌ libsignal encryption failed for ${encryptionJid}:`, encryptionError.message)
					console.error(`Session address: ${addr.toString()}`)
					
					// Check if this is the protobuf serialization error
					if (encryptionError.message?.includes('Assertion failed')) {
						// This might be a corrupted session - check if we have an alternate
						if (encryptionJid !== jid) {
							console.log(`🔄 Encryption failed with LID, trying original PN: ${jid}`)
							const origAddr = jidToSignalProtocolAddress(jid)
							const origCipher = new libsignal.SessionCipher(storage, origAddr)
							
							try {
								const { type: sigType, body } = await origCipher.encrypt(data)
								const type = sigType === 3 ? 'pkmsg' : 'msg'
								console.log(`✅ Encryption succeeded with original PN`)
								return { type, ciphertext: Buffer.from(body as any, 'binary') }
							} catch (origError: any) {
								console.error(`❌ Original PN encryption also failed: ${origError.message}`)
								throw encryptionError // Throw original error
							}
						}
					}
					
					throw encryptionError
				}
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
				// Note: No LID cache invalidation needed here - E2E sessions are about encryption keys,
				// not identity mappings. LID-PN relationships are independent of encryption sessions.
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
		},
		/**
		 * Get privacy token manager instance
		 */
		getPrivacyTokenManager() {
			return privacyTokenManager
		},
		/**
		 * Server-coordinated migration - only call when server notifies about LID changes
		 * This is WhatsApp's proper migration approach (prevents Bad MAC errors)
		 */
		async migrateSession(fromJid: string, toJid: string) {
			await coordinatedSessionMigration(fromJid, toJid)
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
				console.log(`🔍 Loading session: ${id}`)
				const { [id]: sess } = await keys.get('session', [id])
				console.log(`📦 Session result for ${id}: ${sess ? 'FOUND' : 'NOT FOUND'}`)
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
			
			// NOTE: LID cache invalidation removed - LID mappings are identity relationships,
			// not session keys. They don't change when cryptographic sessions are updated.
			// LID cache should only be invalidated when:
			// 1. Server sends LID migration notification  
			// 2. Manual cache cleanup/maintenance
			// 3. Contact deletion
			console.log(`💾 Session stored: ${id}`)
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