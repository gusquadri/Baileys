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
	
	
	const hasLIDSession = async (lidJid: string): Promise<boolean> => {
		const lidAddr = jidToSignalProtocolAddress(lidJid)
		const lidSession = await storage.loadSession(lidAddr.toString())
		return !!(lidSession && lidSession.haveOpenSession())
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
		},
		async encryptMessage({ jid, data }) {
			// SAFE APPROACH: NO LID lookups during encryption
			// The Socket layer should determine the correct JID before calling this
			// Migration should happen during MESSAGE RECEPTION, not sending
			
			console.log(`📤 Encrypting for: ${jid}`)
			
			const addr = jidToSignalProtocolAddress(jid)
			const cipher = new libsignal.SessionCipher(storage, addr)
			
			const { type: sigType, body } = await cipher.encrypt(data)
			const type = sigType === 3 ? 'pkmsg' : 'msg'
			
			return { 
				type, 
				ciphertext: Buffer.from(body as any, 'binary')
			}
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
		 * Migrate session from PN to LID - KEEP BOTH SESSIONS
		 * Key principles:
		 * 1. One-way migration only (PN → LID)
		 * 2. Skip if already migrated (check Redis)
		 * 3. Atomic operation within transaction
		 * 4. KEEP both sessions (safer approach)
		 */
		async migrateSession(fromJid: string, toJid: string) {
			// Only migrate PN → LID
			if (!isJidUser(fromJid) || !isLidUser(toJid)) {
				console.log(`🚫 Invalid migration: ${fromJid} → ${toJid} (only PN→LID allowed)`)
				return
			}
			
			// Check if LID session already exists for this device
			if (await hasLIDSession(toJid)) {
				console.log(`✅ LID session already exists: ${toJid}`)
				return
			}
			
			console.log(`🔄 Migrating device session: ${fromJid} → ${toJid}`)
			
			const fromAddr = jidToSignalProtocolAddress(fromJid)
			const toAddr = jidToSignalProtocolAddress(toJid)
			
			// Load PN session for this specific device
			const fromSession = await storage.loadSession(fromAddr.toString())
			if (!fromSession || !fromSession.haveOpenSession()) {
				console.log(`ℹ️ No session to migrate from ${fromJid}`)
				return
			}
			
			// Copy to LID address (keep original) - async-mutex handles concurrency
			await storage.storeSession(toAddr.toString(), fromSession)
			console.log(`✅ Session copied: ${fromAddr} → ${toAddr}`)
			console.log(`🔄 Keeping original session: ${fromAddr}`)
			
			// Store LID mapping
			await lidMapping.storeLIDPNMapping(toJid, fromJid)
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