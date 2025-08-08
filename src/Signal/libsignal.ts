/* @ts-ignore */
import * as libsignal from 'libsignal'
import type { SignalAuthState, SignalKeyStoreWithTransaction } from '../Types'
import type { SignalRepository } from '../Types/Signal'
import { generateSignalPubKey } from '../Utils'
import { jidDecode, isJidUser, isLidUser } from '../WABinary'
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
	
	
	// Migration tracking using Redis for persistence and consistency
	// Following whatsmeow approach: permanent tracking, no TTL
	const getMigrationKey = (fromJid: string): string => {
		// Use Signal address format for consistency with whatsmeow
		const decoded = jidDecode(fromJid)
		if (!decoded) return fromJid
		return `${decoded.user}_migrated` // Add suffix to distinguish from regular LID mappings
	}
	
	const isRecentlyMigrated = async (fromJid: string): Promise<boolean> => {
		const key = getMigrationKey(fromJid)
		const stored = await auth.keys.get('lid-mapping', [key])
		return stored[key] === 'true' // Store as string since lid-mapping expects string values
	}
	
	const markAsMigrated = async (fromJid: string): Promise<void> => {
		const key = getMigrationKey(fromJid)
		await auth.keys.set({
			'lid-mapping': {
				[key]: 'true' // Store migration flag as string
			}
		})
	}
	
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
			
			// 5. Delete old session after successful migration (whatsmeow approach)
			await storage.storeSession(fromAddr.toString(), null)
			
			console.log(`✅ Coordinated migration completed: ${fromJid} → ${toJid}`)
		} catch (error) {
			console.error(`❌ Failed coordinated migration: ${fromJid} → ${toJid}`, error)
			throw error
		}
	}

	/**
	 * Atomic session migration following whatsmeow's approach
	 * Only migrates sessions, not identity/sender keys (simpler, more reliable)
	 */
	const migrateSession = async (fromJid: string, toJid: string): Promise<void> => {
		const fromAddr = jidToSignalProtocolAddress(fromJid)
		const toAddr = jidToSignalProtocolAddress(toJid)
		
		const fromAddrStr = fromAddr.toString()
		const toAddrStr = toAddr.toString()
		
		if (fromAddrStr === toAddrStr) {
			return // No migration needed
		}
		
		// LRU-based deduplication check (optimal pattern for migration tracking)
		const migrationKey = `${fromJid}→${toJid}`
		
		// Check if migration was recently completed
		if (await isRecentlyMigrated(fromJid)) {
			console.log(`✅ Migration already completed: ${migrationKey}`)
			return
		}
		
		// ATOMIC MIGRATION: All operations in single transaction (whatsmeow pattern)
		return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
			try {
				let migrationCount = 0
				const migrationLog: string[] = []
				
				// Check if destination already has a session - if yes, skip migration
				const toSession = await storage.loadSession(toAddrStr)
				if (toSession && toSession.haveOpenSession()) {
					console.log(`✅ Session already exists at ${toJid}, skipping migration`)
					await markAsMigrated(fromJid) // Mark as migrated in Redis
					return
				}
				
				// 1. MIGRATE SIGNAL SESSION (most critical)
				const fromSession = await storage.loadSession(fromAddrStr)
				if (fromSession && fromSession.haveOpenSession()) {
					await storage.storeSession(toAddrStr, fromSession)
					migrationCount++
					migrationLog.push(`session: ${fromAddrStr} → ${toAddrStr}`)
					
					// Delete old session after successful migration (whatsmeow approach)
					await storage.storeSession(fromAddrStr, null)
					migrationLog.push(`deleted old session: ${fromAddrStr}`)
				}
				
				// 4. UPDATE LID MAPPING (Baileys enhancement)
				try {
					await lidMapping.storeLIDPNMapping(toJid, fromJid)
					migrationLog.push(`lid-mapping: ${fromJid} ↔ ${toJid}`)
				} catch (lidError) {
					console.warn(`⚠️ LID mapping update failed: ${lidError}`)
				}
				
				// 5. MIGRATION STATISTICS (whatsmeow pattern)
				if (migrationCount > 0) {
					console.log(`✅ Atomic migration completed: ${fromJid} → ${toJid}`)
					console.log(`   Migrated components (${migrationCount}): ${migrationLog.join(', ')}`)
					await markAsMigrated(fromJid) // Mark as migrated in Redis
				} else {
					console.log(`ℹ️ No components to migrate: ${fromJid} → ${toJid}`)
				}
				
			} catch (error) {
				console.error(`❌ Atomic migration failed: ${fromJid} → ${toJid}`, error)
				throw error // Transaction will rollback
			}
		})
	}


	const repository: SignalRepository = {
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
			console.log(`🔑 Processing sender key distribution for: ${senderNameStr}`)

			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr])
				console.log(`🔍 Existing sender key check: ${senderKey ? 'FOUND' : 'NOT FOUND'}`)
				
				if (!senderKey) {
					console.log(`📝 Creating new sender key record for: ${senderNameStr}`)
					await storage.storeSenderKey(senderName, new SenderKeyRecord())
				}

				console.log(`⚙️ Processing sender key message...`)
				await builder.process(senderName, senderMsg)
				
				// Verify the key was stored
				const { [senderNameStr]: verifyKey } = await auth.keys.get('sender-key', [senderNameStr])
				console.log(`✅ Sender key storage verification: ${verifyKey ? 'SUCCESS' : 'FAILED'}`)
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
			// Simple approach following whatsmeow:
			// 1. Check if we have a stored LID for this PN
			// 2. Use LID if available, otherwise use PN
			// 3. No complex priority logic or migration during encryption
			
			let encryptionJid = jid
			
			// Skip LID lookup for non-user JIDs or bots
			if (isJidUser(jid) && !jid.includes('bot')) {
				try {
					const lidStore = repository.getLIDMappingStore()
					const storedLid = await lidStore.getLIDForPN(jid)
					
					if (storedLid && isLidUser(storedLid)) {
						console.log(`📤 Using stored LID for encryption: ${jid} → ${storedLid}`)
						encryptionJid = storedLid
					}
				} catch (error) {
					console.warn(`⚠️ Failed to lookup LID for ${jid}:`, error)
				}
			}
			
			console.log(`📤 Encrypting for: ${encryptionJid}`)
			
			const addr = jidToSignalProtocolAddress(encryptionJid)
			const cipher = new libsignal.SessionCipher(storage, addr)
			
			// Simple encryption - let it fail if session doesn't exist
			// The retry mechanism will handle session creation
			const { type: sigType, body } = await cipher.encrypt(data)
			const type = sigType === 3 ? 'pkmsg' : 'msg'
			
			return { type, ciphertext: Buffer.from(body as any, 'binary') }
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
		 * Migrate session from PN to LID following whatsmeow's approach
		 * Key principles:
		 * 1. One-way migration only (PN → LID)
		 * 2. Skip if already migrated (check Redis)
		 * 3. Atomic operation within transaction
		 * 4. Delete old session after migration
		 */
		async migrateSession(fromJid: string, toJid: string) {
			// Only migrate PN → LID
			if (!isJidUser(fromJid) || !isLidUser(toJid)) {
				console.log(`🚫 Invalid migration: ${fromJid} → ${toJid} (only PN→LID allowed)`)
				return
			}
			
			// Check if already migrated
			if (await isRecentlyMigrated(fromJid)) {
				console.log(`✅ Already migrated: ${fromJid}`)
				return
			}
			
			console.log(`🔄 Migrating session: ${fromJid} → ${toJid}`)
			
			// Atomic migration in transaction
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const fromAddr = jidToSignalProtocolAddress(fromJid)
				const toAddr = jidToSignalProtocolAddress(toJid)
				
				// Load PN session
				const fromSession = await storage.loadSession(fromAddr.toString())
				if (!fromSession || !fromSession.haveOpenSession()) {
					console.log(`ℹ️ No session to migrate from ${fromJid}`)
					await markAsMigrated(fromJid) // Mark as processed
					return
				}
				
				// Copy to LID address
				await storage.storeSession(toAddr.toString(), fromSession)
				console.log(`✅ Session copied: ${fromAddr} → ${toAddr}`)
				
				// Delete old PN session
				await storage.storeSession(fromAddr.toString(), null)
				console.log(`🗑️ Deleted old session: ${fromAddr}`)
				
				// Mark as migrated in Redis
				await markAsMigrated(fromJid)
				
				// Store LID mapping
				await lidMapping.storeLIDPNMapping(toJid, fromJid)
			})
		}
	}

	return repository
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
			console.log(`💾 Storing sender key: ${keyId}`)
			
			const serialized = key.serialize()
			console.log(`📊 Serialized sender key states: ${serialized.length} states`)
			
			const jsonStr = JSON.stringify(serialized)
			const buffer = Buffer.from(jsonStr, 'utf-8')
			
			console.log(`📦 Buffer size: ${buffer.length} bytes`)
			
			await keys.set({ 'sender-key': { [keyId]: buffer } })
			console.log(`✅ Sender key stored: ${keyId}`)
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