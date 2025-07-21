import * as libsignal from 'libsignal'
import { SignalAuthState, SignalKeyStoreWithTransaction } from '../Types'
import { SignalRepository } from '../Types/Signal'
import { generateSignalPubKey } from '../Utils'
import { jidDecode } from '../WABinary'
import type { SenderKeyStoreWithQueue } from './Group/group_cipher'
import { SenderKeyName } from './Group/sender-key-name'
import { SenderKeyRecord } from './Group/sender-key-record'
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage } from './Group'

export function makeLibSignalRepository(auth: SignalAuthState): SignalRepository {
	const storage: SenderKeyStoreWithQueue = signalStorage(auth)
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
				const { [senderNameStr]: existingSenderKey } = await auth.keys.get('sender-key', [senderNameStr])
				
				console.log(`[SENDER_KEY_DEBUG] Processing distribution for ${senderNameStr}, existing: ${!!existingSenderKey}`)
				
				// Only create new sender key record if none exists
				// This prevents race conditions with concurrent key operations
				if (!existingSenderKey) {
					const newRecord = new SenderKeyRecord()
					await storage.storeSenderKey(senderName, newRecord)
					console.log(`[SENDER_KEY_DEBUG] Created new sender key record for ${senderNameStr}`)
				}

				await builder.process(senderName, senderMsg)
				console.log(`[SENDER_KEY_DEBUG] Processed sender key distribution for ${senderNameStr}`)
			})
		},
		async decryptMessage({ jid, type, ciphertext }) {
			const addr = jidToSignalProtocolAddress(jid)
			const session = new libsignal.SessionCipher(storage, addr)
			const sessionId = addr.toString()

			console.log(`[CHAT_KEY_DEBUG] Decrypting ${type} message from ${jid} (session: ${sessionId})`)

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				// Check if session exists before decryption
				const { [sessionId]: existingSession } = await auth.keys.get('session', [sessionId])
				console.log(`[CHAT_KEY_DEBUG] Existing session for ${jid}: ${!!existingSession}`)

				let result: Buffer
				switch (type) {
					case 'pkmsg':
						console.log(`[CHAT_KEY_DEBUG] Decrypting pre-key message from ${jid}`)
						result = await session.decryptPreKeyWhisperMessage(ciphertext)
						break
					case 'msg':
						console.log(`[CHAT_KEY_DEBUG] Decrypting whisper message from ${jid}`)
						result = await session.decryptWhisperMessage(ciphertext)
						break
				}

				console.log(`[CHAT_KEY_DEBUG] Successfully decrypted message from ${jid}`)
				return result
			})
		},
		async encryptMessage({ jid, data }) {
			const addr = jidToSignalProtocolAddress(jid)
			const cipher = new libsignal.SessionCipher(storage, addr)
			const sessionId = addr.toString()

			console.log(`[CHAT_KEY_DEBUG] Encrypting message to ${jid} (session: ${sessionId})`)

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				// Check if session exists before encryption
				const { [sessionId]: existingSession } = await auth.keys.get('session', [sessionId])
				console.log(`[CHAT_KEY_DEBUG] Existing session for ${jid}: ${!!existingSession}`)

				const { type: sigType, body } = await cipher.encrypt(data)
				const type = sigType === 3 ? 'pkmsg' : 'msg'
				
				console.log(`[CHAT_KEY_DEBUG] Encrypted as ${type} message to ${jid}`)
				return { type, ciphertext: Buffer.from(body, 'binary') }
			})
		},
		async encryptGroupMessage({ group, meId, data }) {
			const senderName = jidToSignalSenderKeyName(group, meId)
			const builder = new GroupSessionBuilder(storage)

			const senderNameStr = senderName.toString()

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { [senderNameStr]: existingSenderKey } = await auth.keys.get('sender-key', [senderNameStr])
				
				console.log(`[SENDER_KEY_DEBUG] Encrypting group message for ${senderNameStr}, existing: ${!!existingSenderKey}`)
				
				// Only create new sender key record if none exists
				// This prevents overwriting keys that might be in the process of being set up
				if (!existingSenderKey) {
					const newRecord = new SenderKeyRecord()
					await storage.storeSenderKey(senderName, newRecord)
					console.log(`[SENDER_KEY_DEBUG] Created new sender key record for encryption ${senderNameStr}`)
				}

				const senderKeyDistributionMessage = await builder.create(senderName)
				const session = new GroupCipher(storage, senderName)
				const ciphertext = await session.encrypt(data)

				console.log(`[SENDER_KEY_DEBUG] Successfully encrypted group message for ${senderNameStr}`)

				return {
					ciphertext,
					senderKeyDistributionMessage: senderKeyDistributionMessage.serialize()
				}
			})
		},
		async injectE2ESession({ jid, session }) {
			const cipher = new libsignal.SessionBuilder(storage, jidToSignalProtocolAddress(jid))
			const sessionId = jidToSignalProtocolAddress(jid).toString()

			console.log(`[CHAT_KEY_DEBUG] Injecting E2E session for ${jid} (session: ${sessionId})`)

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { [sessionId]: existingSession } = await auth.keys.get('session', [sessionId])
				console.log(`[CHAT_KEY_DEBUG] Existing session before injection for ${jid}: ${!!existingSession}`)

				await cipher.initOutgoing(session)
				console.log(`[CHAT_KEY_DEBUG] Successfully injected E2E session for ${jid}`)
			})
		},
		jidToSignalProtocolAddress(jid) {
			return jidToSignalProtocolAddress(jid).toString()
		}
	}
}

const jidToSignalProtocolAddress = (jid: string) => {
	const { user, device } = jidDecode(jid)!
	return new libsignal.ProtocolAddress(user, device || 0)
}

const jidToSignalSenderKeyName = (group: string, user: string): SenderKeyName => {
	return new SenderKeyName(group, jidToSignalProtocolAddress(user))
}

function signalStorage({ creds, keys }: SignalAuthState): SenderKeyStoreWithQueue & Record<string, unknown> {
	return {
		loadSession: async (id: string) => {
			const { [id]: sess } = await keys.get('session', [id])
			if (sess) {
				return libsignal.SessionRecord.deserialize(sess)
			}
		},
		storeSession: async (id: string, session: libsignal.SessionRecord) => {
			await keys.set({ session: { [id]: session.serialize() } })
		},
		isTrustedIdentity: () => {
			return true
		},
		loadPreKey: async (id: number | string) => {
			const keyId = id.toString()
			const { [keyId]: key } = await keys.get('pre-key', [keyId])
			if (key) {
				return {
					privKey: Buffer.from(key.private),
					pubKey: Buffer.from(key.public)
				}
			}
		},
		removePreKey: (id: number) => keys.set({ 'pre-key': { [id]: null } }),
		loadSignedPreKey: () => {
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
		getOurRegistrationId: () => creds.registrationId,
		getOurIdentity: () => {
			const { signedIdentityKey } = creds
			return {
				privKey: Buffer.from(signedIdentityKey.private),
				pubKey: generateSignalPubKey(signedIdentityKey.public)
			}
		},
		queueGroupMessage: 'queueGroupMessage' in keys ? keys.queueGroupMessage : undefined
	}
}
