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
				
				// Only create new sender key record if none exists
				// This prevents race conditions with concurrent key operations
				if (!existingSenderKey) {
					const newRecord = new SenderKeyRecord()
					await storage.storeSenderKey(senderName, newRecord)
				}

				await builder.process(senderName, senderMsg)
			})
		},
		async decryptMessage({ jid, type, ciphertext }) {
			const addr = jidToSignalProtocolAddress(jid)
			const session = new libsignal.SessionCipher(storage, addr)
			const sessionId = addr.toString()

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { [sessionId]: existingSession } = await auth.keys.get('session', [sessionId])

				// For regular messages, wait briefly if no session exists
				// This prevents race conditions with concurrent session operations
				if (type === 'msg' && !existingSession) {
					// Wait a short time for potential concurrent session creation
					await new Promise(resolve => setTimeout(resolve, 100))
				}

				let result: Buffer
				switch (type) {
					case 'pkmsg':
						result = await session.decryptPreKeyWhisperMessage(ciphertext)
						break
					case 'msg':
						result = await session.decryptWhisperMessage(ciphertext)
						break
				}

				return result
			})
		},
		async encryptMessage({ jid, data }) {
			const addr = jidToSignalProtocolAddress(jid)
			const cipher = new libsignal.SessionCipher(storage, addr)
			const sessionId = addr.toString()

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { [sessionId]: existingSession } = await auth.keys.get('session', [sessionId])

				// Wait briefly if no session exists
				// This prevents creating sessions during encryption
				if (!existingSession) {
					// Wait a short time for potential concurrent session creation
					await new Promise(resolve => setTimeout(resolve, 100))
				}

				const { type: sigType, body } = await cipher.encrypt(data)
				const type = sigType === 3 ? 'pkmsg' : 'msg'
				
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
				
				// Only create new sender key record if none exists
				// This prevents overwriting keys that might be in the process of being set up
				if (!existingSenderKey) {
					const newRecord = new SenderKeyRecord()
					await storage.storeSenderKey(senderName, newRecord)
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
			const sessionId = jidToSignalProtocolAddress(jid).toString()

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { [sessionId]: existingSession } = await auth.keys.get('session', [sessionId])

				// Wait briefly if session exists to prevent race conditions
				// This allows concurrent operations to complete before overwriting
				if (existingSession) {
					await new Promise(resolve => setTimeout(resolve, 100))
				}

				await cipher.initOutgoing(session)
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
		storeSession: async (id: string, session: any) => {
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
