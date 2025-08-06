/* @ts-ignore */
import * as libsignal from 'libsignal'
import type { SignalAuthState, SignalKeyStoreWithTransaction } from '../Types'
import type { SignalRepository } from '../Types/Signal'
import { generateSignalPubKey } from '../Utils'
import { jidDecode, jidEncode } from '../WABinary'
import { LIDMappingStore } from '../Utils/lid-mapping'
import { PrivacyTokenManager } from './privacy-tokens'
import type { SenderKeyStore } from './Group/group_cipher'
import { SenderKeyName } from './Group/sender-key-name'
import { SenderKeyRecord } from './Group/sender-key-record'
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage } from './Group'
import type { StorageType } from 'libsignal'

export function makeLibSignalRepository(auth: SignalAuthState): SignalRepository {
	const lidMapping = new LIDMappingStore(auth.keys as SignalKeyStoreWithTransaction)
	const storage : StorageType & SenderKeyStore = signalStorage(auth, lidMapping)
	
	// Initialize privacy token manager for session migration (following whatsmeow approach)
	const privacyTokenManager = new PrivacyTokenManager(auth.keys as SignalKeyStoreWithTransaction, lidMapping)
	
	// Link managers for cross-referencing (avoiding circular dependency)
	lidMapping.setPrivacyTokenManager(privacyTokenManager)
	
	/**
	 * Reactive session migration - migrate when contact changes type
	 * Based on whatsmeow's approach
	 */
	const reactiveSessionMigration = async (recipientJid: string): Promise<string> => {
		const { server, user } = jidDecode(recipientJid)!
		
		// Determine current contact type from JID
		const isLidContact = server === 'lid'
		const currentJid = recipientJid
		
		// Determine alternative JID format for this contact
		const alternativeJid = isLidContact 
			? jidEncode(user, 's.whatsapp.net')  // LID -> PN format
			: jidEncode(user, 'lid')             // PN -> LID format
		
		// Check if we have sessions in both formats (indicates type change)
		const currentAddr = jidToSignalProtocolAddress(currentJid)
		const alternativeAddr = jidToSignalProtocolAddress(alternativeJid)
		
		const currentSession = await storage.loadSession(currentAddr.toString())
		const alternativeSession = await storage.loadSession(alternativeAddr.toString())
		
		const hasCurrentSession = currentSession && currentSession.haveOpenSession()
		const hasAlternativeSession = alternativeSession && alternativeSession.haveOpenSession()
		
		if (hasAlternativeSession && !hasCurrentSession) {
			// Contact changed type! Migrate session
			console.log(`🔄 Reactive migration: ${alternativeJid} → ${currentJid}`)
			
			try {
				// Copy session to new format
				await storage.storeSession(currentAddr.toString(), alternativeSession)
				
				// Migrate privacy token (critical for maintaining authorization - whatsmeow approach)
				try {
					await privacyTokenManager.migratePrivacyToken(alternativeJid, currentJid)
					console.log(`🔐 Privacy token migrated: ${alternativeJid} → ${currentJid}`)
				} catch (tokenError) {
					console.warn(`⚠️ Privacy token migration failed (non-critical): ${alternativeJid} → ${currentJid}`, tokenError)
					// Don't fail session migration for token issues
				}
				
				// Update LID mapping cache to reflect the type change
				if (isLidContact) {
					// Contact switched to LID - store the mapping
					const pnJid = jidEncode(user, 's.whatsapp.net')
					await lidMapping.storeLIDPNMapping(currentJid, pnJid)
					console.log(`📝 Stored LID mapping: ${currentJid} ↔ ${pnJid}`)
				} else {
					// Contact switched to PN - update cache
					lidMapping.invalidateContact(alternativeJid)
					console.log(`🗑️ Invalidated old LID mapping for: ${alternativeJid}`)
				}
				
				console.log(`✅ Session migrated successfully: ${alternativeJid} → ${currentJid}`)
			} catch (error) {
				console.error(`❌ Failed to migrate session: ${alternativeJid} → ${currentJid}`, error)
			}
		}
		
		return currentJid
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

	/**
	 * Find and migrate LID sessions for decryption
	 */
	const findSessionForDecryption = async (jid: string): Promise<string> => {
		const addr = jidToSignalProtocolAddress(jid)
		const addrStr = addr.toString()
		
		// First try the provided JID
		const existingSession = await storage.loadSession(addrStr)
		if (existingSession && existingSession.haveOpenSession()) {
			console.log(`✅ Session found and active for ${jid}`)
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
			// DISABLE REACTIVE MIGRATION TO PREVENT DOUBLE RATCHET ISSUES
			// Use original JID for decryption to maintain session consistency
			const decryptionJid = jid
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
			// Get user info for optimizations
			const authCreds = (auth as any).creds || auth
			const ownPhoneNumber = authCreds.me?.id?.split('@')[0]?.split(':')[0]
			const targetUser = jidDecode(jid)?.user
			
			let encryptionJid = jid
			
			// DISABLE REACTIVE MIGRATION TO PREVENT DOUBLE RATCHET ISSUES  
			// Keep original JID for encryption to maintain session consistency
			console.log(`📤 Encrypting message to: ${encryptionJid} (migration disabled)`)
			
			const addr = jidToSignalProtocolAddress(encryptionJid)
			const cipher = new libsignal.SessionCipher(storage, addr)

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				try {
					const { type: sigType, body } = await cipher.encrypt(data)
					const type = sigType === 3 ? 'pkmsg' : 'msg'
					return { type, ciphertext: Buffer.from(body as any, 'binary') }
				} catch (error: any) {
					// Handle assertion failures and corrupted sessions
					if (error.message?.includes('Assertion failed') || error.message?.includes('serialize')) {
						console.error(`⚠️ Session corruption detected for ${encryptionJid}, clearing session`)
						
						// Clear the corrupted session
						const addrStr = addr.toString()
						await storage.storeSession(addrStr, null)
						
						// Clear cache to force fresh session establishment
						if (LIDMappingStore.isLID(encryptionJid)) {
							lidMapping.invalidateContact(encryptionJid)
						} else if (LIDMappingStore.isPN(encryptionJid)) {
							lidMapping.invalidateContact(encryptionJid)
						}
						
						// Throw a more descriptive error
						throw new Error(`Session corrupted for ${encryptionJid}. Please retry - a new session will be established.`)
					}
					
					// Re-throw other errors
					throw error
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

function signalStorage({ creds, keys }: SignalAuthState, lidMappingStore: LIDMappingStore): StorageType & SenderKeyStore & Record<string, any> {
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
			
			// CRITICAL: Invalidate LID mapping cache when session is updated
			// This prevents using outdated cached sessions after new keys are received
			try {
				console.log(`🗑️ Session stored: ${id} - invalidating LID cache`)
				
				// Extract JID from session ID and invalidate only the relevant contact
				const sessionParts = id.split('.')
				if (sessionParts.length >= 1 && sessionParts[0]) {
					const baseId = sessionParts[0]
					
					// Convert session ID back to JID and invalidate
					if (baseId.includes('_1')) {
						// LID session format: "102765716062358_1" → "102765716062358@lid"
						const lidUser = baseId.replace('_1', '')
						const lidJid = `${lidUser}@lid`
						lidMappingStore.invalidateContact(lidJid)
						console.log(`🗑️ Invalidated LID cache for: ${lidJid}`)
					} else {
						// Regular PN session format: "554391318447" → "554391318447@s.whatsapp.net"  
						const pnJid = `${baseId}@s.whatsapp.net`
						lidMappingStore.invalidateContact(pnJid)
						console.log(`🗑️ Invalidated PN cache for: ${pnJid}`)
					}
				}
			} catch (error) {
				console.warn('Failed to invalidate LID mapping cache:', error)
			}
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