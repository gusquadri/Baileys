import * as libsignal from 'libsignal'
import { SignalAuthState, SignalKeyStoreWithTransaction } from '../Types'
import { SignalRepository } from '../Types/Signal'
import { generateSignalPubKey } from '../Utils'
import { jidDecode } from '../WABinary'
import type { SenderKeyStore } from './Group/group_cipher'
import { SenderKeyName } from './Group/sender-key-name'
import { SenderKeyRecord } from './Group/sender-key-record'
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage } from './Group'

export function makeLibSignalRepository(auth: SignalAuthState): SignalRepository {
	const storage: SenderKeyStore = signalStorage(auth)
	return {
		decryptGroupMessage({ group, authorJid, msg }) {
			const senderName = jidToSignalSenderKeyName(group, authorJid)
			const cipher = new GroupCipher(storage, senderName)

			return cipher.decrypt(msg)
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
			const addr = jidToSignalProtocolAddress(jid)
			const session = new libsignal.SessionCipher(storage, addr)

			// Use transaction to ensure atomicityAdd commentMore actions
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
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

			// Use transaction to ensure atomicityAdd commentMore actions
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { type: sigType, body } = await cipher.encrypt(data)
				const type = sigType === 3 ? 'pkmsg' : 'msg'
				return { type, ciphertext: Buffer.from(body, 'binary') }
			})
		},
		async encryptGroupMessage({ group, meId, data }) {
			console.log('🔐 [encryptGroupMessage] Starting encryption for group:', group, 'meId:', meId, 'dataLength:', data?.length)
			
			const senderName = jidToSignalSenderKeyName(group, meId)
			const builder = new GroupSessionBuilder(storage)

			const senderNameStr = senderName.toString()
			console.log('🔐 [encryptGroupMessage] SenderName:', senderNameStr)

			// Check if already in transaction to avoid nested transactions
			const executeEncryption = async () => {
				console.log('🔐 [encryptGroupMessage] Starting executeEncryption, inTransaction:', (auth.keys as SignalKeyStoreWithTransaction).isInTransaction())
				
				const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr])
				console.log('🔐 [encryptGroupMessage] Retrieved sender key, exists:', !!senderKey)
				
				if (!senderKey) {
					console.log('🔐 [encryptGroupMessage] Creating new SenderKeyRecord')
					await storage.storeSenderKey(senderName, new SenderKeyRecord())
				}

				console.log('🔐 [encryptGroupMessage] Creating sender key distribution message')
				const senderKeyDistributionMessage = await builder.create(senderName)
				
				console.log('🔐 [encryptGroupMessage] Creating GroupCipher session')
				const session = new GroupCipher(storage, senderName)
				
				console.log('🔐 [encryptGroupMessage] Encrypting data')
				const ciphertext = await session.encrypt(data)
				
				console.log('🔐 [encryptGroupMessage] Encryption successful, ciphertext length:', ciphertext?.length)

				return {
					ciphertext,
					senderKeyDistributionMessage: senderKeyDistributionMessage.serialize()
				}
			}

			try {
				// Only start transaction if not already in one
				if ((auth.keys as SignalKeyStoreWithTransaction).isInTransaction()) {
					console.log('🔐 [encryptGroupMessage] Already in transaction, executing directly')
					return await executeEncryption()
				} else {
					console.log('🔐 [encryptGroupMessage] Starting new transaction')
					return await (auth.keys as SignalKeyStoreWithTransaction).transaction(executeEncryption)
				}
			} catch (error) {
				console.error('🔐 [encryptGroupMessage] ERROR:', error)
				throw error
			}
		},
		async injectE2ESession({ jid, session }) {
			const cipher = new libsignal.SessionBuilder(storage, jidToSignalProtocolAddress(jid))

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
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

function signalStorage({ creds, keys }: SignalAuthState): SenderKeyStore & Record<string, any> {
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
		}
	}
}
