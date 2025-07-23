import NodeCache from '@cacheable/node-cache'
import { Mutex } from 'async-mutex'
import { randomBytes } from 'crypto'
import { DEFAULT_CACHE_TTLS } from '../Defaults'
import type {
	AuthenticationCreds,
	CacheStore,
	SignalDataSet,
	SignalDataTypeMap,
	SignalKeyStore,
	SignalKeyStoreWithTransaction,
	TransactionCapabilityOptions
} from '../Types'
import { Curve, signedKeyPair } from './crypto'
import { delay, generateRegistrationId } from './generics'
import { ILogger } from './logger'

interface QueuedGroupMessage {
	senderKeyName: string
	messageBytes: Uint8Array
	resolve: (result: Uint8Array) => void
	reject: (error: Error) => void
	timestamp: number
	originalCipher: {
		decrypt: (messageBytes: Uint8Array) => Promise<Uint8Array>
	}
}

interface MessageQueueConfig {
	messageTimeoutMs: number
}

/**
 * Adds caching capability to a SignalKeyStore.
 * This is a helper function and remains unchanged.
 */
export function makeCacheableSignalKeyStore(
	store: SignalKeyStore,
	logger?: ILogger,
	_cache?: CacheStore
): SignalKeyStore {
	const cache =
		_cache ||
		new NodeCache({
			stdTTL: DEFAULT_CACHE_TTLS.SIGNAL_STORE, // 5 minutes
			useClones: false,
			deleteOnExpire: true
		})

	const cacheMutex = new Mutex()

	function getUniqueId(type: string, id: string) {
		return `${type}.${id}`
	}

	return {
		async get(type, ids) {
			return cacheMutex.runExclusive(async () => {
				const data: { [_: string]: SignalDataTypeMap[typeof type] } = {}
				const idsToFetch: string[] = []
				for (const id of ids) {
					const item = cache.get<SignalDataTypeMap[typeof type]>(getUniqueId(type, id))
					if (typeof item !== 'undefined') {
						data[id] = item
					} else {
						idsToFetch.push(id)
					}
				}

				if (idsToFetch.length) {
					logger?.trace({ items: idsToFetch.length }, 'loading from store')
					const fetched = await store.get(type, idsToFetch)
					for (const id of idsToFetch) {
						const item = fetched[id]
						if (item) {
							data[id] = item
							cache.set(getUniqueId(type, id), item)
						}
					}
				}

				return data
			})
		},
		async set(data) {
			return cacheMutex.runExclusive(async () => {
				let keys = 0
				for (const type in data) {
					for (const id in data[type]) {
						cache.set(getUniqueId(type, id), data[type][id])
						keys += 1
					}
				}

				logger?.trace({ keys }, 'updated cache')
				await store.set(data)
			})
		},
		async clear() {
			return cacheMutex.runExclusive(async () => {
				cache.flushAll()
				await store.clear?.()
			})
		}
	}
}

// These helper functions remain unchanged as they don't depend on the transaction state.
const preKeyMutex = new Mutex()
const signedPreKeyMutex = new Mutex()
const getPreKeyMutex = (keyType: string): Mutex => (keyType === 'signed-pre-key' ? signedPreKeyMutex : preKeyMutex)

async function handlePreKeyOperations(
	data: SignalDataSet,
	keyType: string,
	transactionCache: SignalDataSet,
	mutations: SignalDataSet,
	logger: ILogger,
	isInTransaction: boolean,
	state?: SignalKeyStore
): Promise<void> {
	const mutex = getPreKeyMutex(keyType)
	await mutex.runExclusive(async () => {
		const keyData = data[keyType]
		if (!keyData) return
		transactionCache[keyType] = transactionCache[keyType] || {}
		mutations[keyType] = mutations[keyType] || {}
		const deletionKeys: string[] = []
		const updateKeys: string[] = []
		for (const keyId in keyData) {
			if (keyData[keyId] === null) {
				deletionKeys.push(keyId)
			} else {
				updateKeys.push(keyId)
			}
		}

		for (const keyId of updateKeys) {
			transactionCache[keyType][keyId] = keyData[keyId]
			mutations[keyType][keyId] = keyData[keyId]
		}

		if (deletionKeys.length === 0) return
		if (isInTransaction) {
			for (const keyId of deletionKeys) {
				if (transactionCache[keyType][keyId]) {
					transactionCache[keyType][keyId] = null
					mutations[keyType][keyId] = null
				} else {
					logger.warn(`Skipping deletion of non-existent ${keyType} in transaction: ${keyId}`)
				}
			}

			return
		}

		if (!state) return
		const existingKeys = await state.get(keyType as keyof SignalDataTypeMap, deletionKeys)
		for (const keyId of deletionKeys) {
			if (existingKeys[keyId]) {
				transactionCache[keyType][keyId] = null
				mutations[keyType][keyId] = null
			} else {
				logger.warn(`Skipping deletion of non-existent ${keyType}: ${keyId}`)
			}
		}
	})
}

function handleNormalKeyOperations(
	data: SignalDataSet,
	key: string,
	transactionCache: SignalDataSet,
	mutations: SignalDataSet
) {
	Object.assign(transactionCache[key], data[key])
	mutations[key] = mutations[key] || {}
	Object.assign(mutations[key], data[key])
}

async function processPreKeyDeletions(
	data: SignalDataSet,
	keyType: string,
	state: SignalKeyStore,
	logger: ILogger
): Promise<void> {
	const mutex = getPreKeyMutex(keyType)
	await mutex.runExclusive(async () => {
		const keyData = data[keyType]
		if (!keyData) return
		for (const keyId in keyData) {
			if (keyData[keyId] === null) {
				const existingKeys = await state.get(keyType as keyof SignalDataTypeMap, [keyId])
				if (!existingKeys[keyId]) {
					logger.warn(`Skipping deletion of non-existent ${keyType}: ${keyId}`)
					delete data[keyType][keyId]
				}
			}
		}
	})
}

async function withMutexes<T>(
	keyTypes: string[],
	getKeyTypeMutex: (type: string) => Mutex,
	fn: () => Promise<T>
): Promise<T> {
	if (keyTypes.length === 0) return fn()
	if (keyTypes.length === 1) return getKeyTypeMutex(keyTypes[0]).runExclusive(fn)
	const sortedKeyTypes = [...keyTypes].sort()
	const mutexes = sortedKeyTypes.map(getKeyTypeMutex)
	const releases: (() => void)[] = []
	try {
		for (const mutex of mutexes) {
			releases.push(await mutex.acquire())
		}

		return await fn()
	} finally {
		while (releases.length > 0) {
			const release = releases.pop()
			if (release) release()
		}
	}
}

async function commitWithRetry(
	mutations: SignalDataSet,
	state: SignalKeyStore,
	getKeyTypeMutex: (type: string) => Mutex,
	maxRetries: number,
	delayMs: number,
	logger: ILogger
): Promise<void> {
	let tries = maxRetries
	while (tries > 0) {
		tries -= 1
		try {
			await withMutexes(Object.keys(mutations), getKeyTypeMutex, async () => {
				await state.set(mutations)
				logger.trace('committed transaction')
			})
			break
		} catch (error) {
			logger.warn(`failed to commit ${Object.keys(mutations).length} mutations, tries left=${tries}`)
			if (tries > 0) {
				await delay(delayMs)
			} else {
				throw error
			}
		}
	}
}

/**
 * Adds DB like transaction capability to the SignalKeyStore.
 * Uses simple shared state approach like the working previous version.
 */
export const addTransactionCapability = (
	state: SignalKeyStore,
	logger: ILogger,
	{ maxCommitRetries, delayBetweenTriesMs }: TransactionCapabilityOptions,
	messageQueueConfig: MessageQueueConfig = {
		messageTimeoutMs: 30000
	}
): SignalKeyStoreWithTransaction => {
	// Mutex for each key type (session, pre-key, etc.)
	const keyTypeMutexes = new Map<string, Mutex>()

	// Per-sender-key-name mutexes for fine-grained serialization
	const senderKeyMutexes = new NodeCache({
		stdTTL: 1800, // 30 minutes TTL for sender key mutexes
		useClones: false,
		deleteOnExpire: true,
		maxKeys: 2000 // Limit to prevent excessive memory usage
	}) as NodeCache & {
		get(key: string): Mutex | undefined
		set(key: string, value: Mutex): void
	}

	// Global transaction mutex
	const transactionMutex = new Mutex()

	// Simple transaction state (like working version)
	let dbQueriesInTransaction = 0
	let transactionCache: SignalDataSet = {}
	let mutations: SignalDataSet = {}
	let transactionsInProgress = 0

	const messageQueue = new Map<string, QueuedGroupMessage[]>()

	// Get or create a mutex for a specific key type
	function getKeyTypeMutex(type: string): Mutex {
		let mutex = keyTypeMutexes.get(type)
		if (!mutex) {
			mutex = new Mutex()
			keyTypeMutexes.set(type, mutex)
		}

		return mutex
	}

	function getSenderKeyMutex(senderKeyName: string): Mutex {
		let mutex = senderKeyMutexes.get(senderKeyName)
		if (!mutex) {
			mutex = new Mutex()
			senderKeyMutexes.set(senderKeyName, mutex)
			logger.info({ senderKeyName }, 'created new sender key mutex')
		}

		return mutex
	}

	function queueSenderKeyOperation<T>(senderKeyName: string, operation: () => Promise<T>): Promise<T> {
		return getSenderKeyMutex(senderKeyName).runExclusive(operation)
	}

	async function queueMessage(
		senderKeyName: string,
		messageBytes: Uint8Array,
		originalCipher: { decrypt: (messageBytes: Uint8Array) => Promise<Uint8Array> }
	): Promise<Uint8Array> {
		return getSenderKeyMutex(senderKeyName).runExclusive(async () => {
			const queue = messageQueue.get(senderKeyName) || []
			return new Promise<Uint8Array>((resolve, reject) => {
				const queuedMessage: QueuedGroupMessage = {
					senderKeyName,
					messageBytes,
					resolve,
					reject,
					timestamp: Date.now(),
					originalCipher
				}
				queue.push(queuedMessage)
				messageQueue.set(senderKeyName, queue)
				logger.debug({ senderKeyName, queueSize: queue.length }, 'message queued for sender key')
				setTimeout(() => {
					getSenderKeyMutex(senderKeyName)
						.runExclusive(async () => {
							const currentQueue = messageQueue.get(senderKeyName) || []
							const messageIndex = currentQueue.findIndex(m => m === queuedMessage)
							if (messageIndex !== -1) {
								currentQueue.splice(messageIndex, 1)
								if (currentQueue.length === 0) {
									messageQueue.delete(senderKeyName)
								} else {
									messageQueue.set(senderKeyName, currentQueue)
								}

								reject(new Error('Message timeout - sender key not received'))
							}
						})
						.catch(() => {})
				}, messageQueueConfig.messageTimeoutMs)
			})
		})
	}

	async function processQueuedMessages(senderKeyName: string): Promise<void> {
		return getSenderKeyMutex(senderKeyName).runExclusive(async () => {
			const queue = messageQueue.get(senderKeyName)
			if (!queue || queue.length === 0) return
			logger.debug({ senderKeyName, queueSize: queue.length }, 'processing queued messages')
			for (const queuedMessage of queue) {
				try {
					const result = await queuedMessage.originalCipher.decrypt(queuedMessage.messageBytes)
					queuedMessage.resolve(result)
				} catch (error) {
					logger.warn({ senderKeyName, error: error.message }, 'queued message still failed after sender key available')
					queuedMessage.reject(error as Error)
				}
			}

			messageQueue.delete(senderKeyName)
		})
	}

	// Check if we are currently in a transaction
	function isInTransaction() {
		return transactionsInProgress > 0
	}

	return {
		get: async (type, ids) => {
			if (isInTransaction()) {
				const dict = transactionCache[type]
				const idsRequiringFetch = dict ? ids.filter(item => typeof dict[item] === 'undefined') : ids
				// only fetch if there are any items to fetch
				if (idsRequiringFetch.length) {
					dbQueriesInTransaction += 1

					// Use per-sender-key queue for sender-key operations when possible
					if (type === 'sender-key') {
						logger.info({ idsRequiringFetch }, 'processing sender keys in transaction')
						// For sender keys, process each one with queued operations to maintain serialization
						for (const senderKeyName of idsRequiringFetch) {
							await queueSenderKeyOperation(senderKeyName, async () => {
								logger.info({ senderKeyName }, 'fetching sender key in transaction')
								const result = await state.get(type, [senderKeyName])
								// Update transaction cache
								transactionCache[type] ||= {}
								Object.assign(transactionCache[type]!, result)
								logger.info({ senderKeyName, hasResult: !!result[senderKeyName] }, 'sender key fetch complete')
							})
						}
					} else {
						// Use runExclusive for cleaner mutex handling
						await getKeyTypeMutex(type as string).runExclusive(async () => {
							const result = await state.get(type, idsRequiringFetch)

							// Update transaction cache
							transactionCache[type] ||= {}
							Object.assign(transactionCache[type]!, result)
						})
					}
				}

				return ids.reduce((dict, id) => {
					const value = transactionCache[type]?.[id]
					if (value) {
						dict[id] = value
					}

					return dict
				}, {})
			} else {
				// Not in transaction, fetch directly with queue protection
				if (type === 'sender-key') {
					// For sender keys, use individual queues to maintain per-key serialization
					const results: { [key: string]: SignalDataTypeMap[typeof type] } = {}
					for (const senderKeyName of ids) {
						const result = await queueSenderKeyOperation(
							senderKeyName,
							async () => await state.get(type, [senderKeyName])
						)
						Object.assign(results, result)
					}

					return results
				} else {
					return await getKeyTypeMutex(type as string).runExclusive(() => state.get(type, ids))
				}
			}
		},
		set: async data => {
			if (isInTransaction()) {
				logger.trace({ types: Object.keys(data) }, 'caching in transaction')
				const senderKeyUpdates: string[] = []
				for (const key in data) {
					transactionCache[key] = transactionCache[key] || {}
					if (key === 'sender-key') {
						const senderKeyData = data[key]
						if (senderKeyData) {
							senderKeyUpdates.push(...Object.keys(senderKeyData))
						}
					}

					if (key === 'pre-key' || key === 'signed-pre-key') {
						await handlePreKeyOperations(data, key, transactionCache, mutations, logger, true)
					} else {
						handleNormalKeyOperations(data, key, transactionCache, mutations)
					}
				}

				for (const senderKeyName of senderKeyUpdates) {
					processQueuedMessages(senderKeyName).catch(error => {
						logger.warn({ senderKeyName, error: error.message }, 'failed to process queued messages in transaction')
					})
				}
			} else {
				// Not in transaction, apply directly with mutex protection
				const hasSenderKeys = 'sender-key' in data
				const senderKeyNames = hasSenderKeys ? Object.keys(data['sender-key'] || {}) : []

				if (hasSenderKeys) {
					logger.info({ senderKeyNames }, 'processing sender key set operations')
					// Handle sender key operations with per-key queues
					for (const senderKeyName of senderKeyNames) {
						await queueSenderKeyOperation(senderKeyName, async () => {
							// Create data subset for this specific sender key
							const senderKeyData = {
								'sender-key': {
									[senderKeyName]: data['sender-key']![senderKeyName]
								}
							}

							logger.trace({ senderKeyName }, 'storing sender key')
							// Apply changes to the store
							await state.set(senderKeyData)
							logger.trace({ senderKeyName }, 'sender key stored')
						})
					}

					// Handle any non-sender-key data with regular mutexes
					const nonSenderKeyData = { ...data }
					delete nonSenderKeyData['sender-key']

					if (Object.keys(nonSenderKeyData).length > 0) {
						await withMutexes(Object.keys(nonSenderKeyData), getKeyTypeMutex, async () => {
							// Process pre-keys and signed-pre-keys separately with specialized mutexes
							for (const keyType in nonSenderKeyData) {
								if (keyType === 'pre-key' || keyType === 'signed-pre-key') {
									await processPreKeyDeletions(nonSenderKeyData, keyType, state, logger)
								}
							}

							// Apply changes to the store
							await state.set(nonSenderKeyData)
						})
					}
				} else {
					// No sender keys - use original logic
					await withMutexes(Object.keys(data), getKeyTypeMutex, async () => {
						// Process pre-keys and signed-pre-keys separately with specialized mutexes
						for (const keyType in data) {
							if (keyType === 'pre-key' || keyType === 'signed-pre-key') {
								await processPreKeyDeletions(data, keyType, state, logger)
							}
						}

						// Apply changes to the store
						await state.set(data)
					})
				}
			}
		},
		isInTransaction,
		...(state.clear ? { clear: state.clear } : {}),
		queueGroupMessage: async (
			senderKeyName: string,
			messageBytes: Uint8Array,
			originalCipher: { decrypt: (messageBytes: Uint8Array) => Promise<Uint8Array> }
		): Promise<Uint8Array> => {
			return queueMessage(senderKeyName, messageBytes, originalCipher)
		},
		async transaction(work) {
			return transactionMutex.acquire().then(async releaseTxMutex => {
				let result: Awaited<ReturnType<typeof work>>
				let mutexReleased = false
				try {
					transactionsInProgress += 1
					if (transactionsInProgress === 1) {
						logger.trace('entering transaction')
					}

					// Release the transaction mutex now that we've updated the counter
					// This allows other transactions to start preparing
					releaseTxMutex()
					mutexReleased = true

					try {
						result = await work()
						// commit if this is the outermost transaction
						if (transactionsInProgress === 1) {
							const hasMutations = Object.keys(mutations).length > 0

							if (hasMutations) {
								logger.trace('committing transaction')
								await commitWithRetry(mutations, state, getKeyTypeMutex, maxCommitRetries, delayBetweenTriesMs, logger)
								logger.trace({ dbQueriesInTransaction }, 'transaction completed')
							} else {
								logger.trace('no mutations in transaction')
							}
						}
					} finally {
						transactionsInProgress -= 1
						if (transactionsInProgress === 0) {
							transactionCache = {}
							mutations = {}
							dbQueriesInTransaction = 0
						}
					}

					return result
				} catch (error) {
					// If we haven't released the transaction mutex yet, release it
					if (!mutexReleased) {
						releaseTxMutex()
					}

					throw error
				}
			})
		}
	}
}

/**
 * Initializes a fresh set of authentication credentials.
 * This function remains unchanged.
 */
export const initAuthCreds = (): AuthenticationCreds => {
	const identityKey = Curve.generateKeyPair()
	return {
		noiseKey: Curve.generateKeyPair(),
		pairingEphemeralKeyPair: Curve.generateKeyPair(),
		signedIdentityKey: identityKey,
		signedPreKey: signedKeyPair(identityKey, 1),
		registrationId: generateRegistrationId(),
		advSecretKey: randomBytes(32).toString('base64'),
		processedHistoryMessages: [],
		nextPreKeyId: 1,
		firstUnuploadedPreKeyId: 1,
		accountSyncCounter: 0,
		accountSettings: {
			unarchiveChats: false
		},
		registered: false,
		pairingCode: undefined,
		lastPropHash: undefined,
		routingInfo: undefined
	}
}
