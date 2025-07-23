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
 * Adds caching capability to a SignalKeyStore
 * @param store the store to add caching to
 * @param logger to log trace events
 * @param _cache cache store to use
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

	// Mutex for protecting cache operations
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

// Module-level specialized mutexes for pre-key operations
const preKeyMutex = new Mutex()
const signedPreKeyMutex = new Mutex()

/**
 * Get the appropriate mutex for the key type
 */
const getPreKeyMutex = (keyType: string): Mutex => {
	return keyType === 'signed-pre-key' ? signedPreKeyMutex : preKeyMutex
}

/**
 * Handles pre-key operations with mutex protection
 */
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

		// Ensure structures exist
		transactionCache[keyType] = transactionCache[keyType] || {}
		mutations[keyType] = mutations[keyType] || {}

		// Separate deletions from updates for batch processing
		const deletionKeys: string[] = []
		const updateKeys: string[] = []

		for (const keyId in keyData) {
			if (keyData[keyId] === null) {
				deletionKeys.push(keyId)
			} else {
				updateKeys.push(keyId)
			}
		}

		// Process updates first (no validation needed)
		for (const keyId of updateKeys) {
			transactionCache[keyType][keyId] = keyData[keyId]
			mutations[keyType][keyId] = keyData[keyId]
		}

		// Process deletions with validation
		if (deletionKeys.length === 0) return

		if (isInTransaction) {
			// In transaction, only allow deletion if key exists in cache
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

		// Outside transaction, batch validate all deletions
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

/**
 * Handles normal key operations for transactions
 */
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

/**
 * Process pre-key deletions with validation
 */
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

		// Validate deletions
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

/**
 * Executes a function with mutexes acquired for given key types
 * Uses async-mutex's runExclusive with efficient batching
 */
async function withMutexes<T>(
	keyTypes: string[],
	getKeyTypeMutex: (type: string) => Mutex,
	fn: () => Promise<T>
): Promise<T> {
	if (keyTypes.length === 0) {
		return fn()
	}

	if (keyTypes.length === 1) {
		return getKeyTypeMutex(keyTypes[0]).runExclusive(fn)
	}

	// For multiple mutexes, sort by key type to prevent deadlocks
	// Then acquire all mutexes in order using Promise.all for better efficiency
	const sortedKeyTypes = [...keyTypes].sort()
	const mutexes = sortedKeyTypes.map(getKeyTypeMutex)

	// Acquire all mutexes in order to prevent deadlocks
	const releases: (() => void)[] = []

	try {
		for (const mutex of mutexes) {
			releases.push(await mutex.acquire())
		}

		return await fn()
	} finally {
		// Release in reverse order
		while (releases.length > 0) {
			const release = releases.pop()
			if (release) release()
		}
	}
}

/**
 * Attempts to commit transaction with retry mechanism
 * Uses async-mutex's withTimeout for better timeout handling
 */
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
			// Use basic withMutexes - withTimeout is for decorating mutexes, not functions
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
				// Re-throw the last error if all retries exhausted
				throw error
			}
		}
	}
}

/**
 * Adds DB like transaction capability (https://en.wikipedia.org/wiki/Database_transaction) to the SignalKeyStore,
 * this allows batch read & write operations & improves the performance of the lib
 * @param state the key store to apply this capability to
 * @param logger logger to log events
 * @returns SignalKeyStore with transaction capability
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

	// Per-sender-key-name mutexes for fine-grained serialization with TTL-based cleanup
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

	// Message queue for pending group messages (per sender key)
	const messageQueue = new Map<string, QueuedGroupMessage[]>()

	// Transaction state stack for nested transaction support
	interface TransactionState {
		cache: SignalDataSet
		mutations: SignalDataSet
		dbQueries: number
	}
	
	const transactionStack: TransactionState[] = []
	let transactionsInProgress = 0
	
	// Get current transaction state (top of stack)
	const getCurrentTransaction = (): TransactionState | null => {
		return transactionStack.length > 0 ? transactionStack[transactionStack.length - 1] : null
	}

	// Get or create a mutex for a specific key type
	function getKeyTypeMutex(type: string): Mutex {
		let mutex = keyTypeMutexes.get(type)
		if (!mutex) {
			// Create regular mutex, timeout only for critical operations
			mutex = new Mutex()
			keyTypeMutexes.set(type, mutex)
		}

		return mutex
	}

	// Get or create a mutex for a specific sender key name
	function getSenderKeyMutex(senderKeyName: string): Mutex {
		let mutex = senderKeyMutexes.get(senderKeyName)
		if (!mutex) {
			mutex = new Mutex()
			senderKeyMutexes.set(senderKeyName, mutex)
			logger.info({ senderKeyName }, 'created new sender key mutex')
		}

		return mutex
	}

	// Sender key operations with proper mutex sequencing
	function queueSenderKeyOperation<T>(senderKeyName: string, operation: () => Promise<T>): Promise<T> {
		return getSenderKeyMutex(senderKeyName).runExclusive(operation)
	}

	/**
	 * Adds a message to the queue for later processing when sender key becomes available
	 */
	async function queueMessage(
		senderKeyName: string,
		messageBytes: Uint8Array,
		originalCipher: { decrypt: (messageBytes: Uint8Array) => Promise<Uint8Array> }
	): Promise<Uint8Array> {
		return getSenderKeyMutex(senderKeyName).runExclusive(async () => {
			const queue = messageQueue.get(senderKeyName) || []

			// Create promise that will be resolved when message is processed
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

				// Set timeout for message
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
						.catch(() => {
							// Ignore mutex errors during cleanup
						})
				}, messageQueueConfig.messageTimeoutMs)
			})
		})
	}

	/**
	 * Processes queued messages for a sender key
	 */
	async function processQueuedMessages(senderKeyName: string): Promise<void> {
		return getSenderKeyMutex(senderKeyName).runExclusive(async () => {
			const queue = messageQueue.get(senderKeyName)
			if (!queue || queue.length === 0) {
				return
			}

			logger.debug({ senderKeyName, queueSize: queue.length }, 'processing queued messages')

			// Process all queued messages - they should succeed now that sender key is available
			for (const queuedMessage of queue) {
				try {
					const result = await queuedMessage.originalCipher.decrypt(queuedMessage.messageBytes)
					queuedMessage.resolve(result)
				} catch (error) {
					logger.warn({ senderKeyName, error: error.message }, 'queued message still failed after sender key available')
					queuedMessage.reject(error as Error)
				}
			}

			// Clean up all processed messages
			messageQueue.delete(senderKeyName)
		})
	}

	// Check if we are currently in a transaction
	function isInTransaction() {
		return transactionsInProgress > 0
	}

	const storeImplementation = {
		get: async <T extends keyof SignalDataTypeMap>(type: T, ids: string[]) => {
			const currentTx = getCurrentTransaction()
			if (currentTx) {
				const dict = currentTx.cache[type]
				const idsRequiringFetch = dict ? ids.filter(item => typeof dict[item] === 'undefined') : ids
				// only fetch if there are any items to fetch
				if (idsRequiringFetch.length) {
					currentTx.dbQueries += 1

					// Use per-sender-key queue for sender-key operations when possible
					if (type === 'sender-key') {
						logger.info({ idsRequiringFetch }, 'processing sender keys in transaction')
						// For sender keys, process each one with queued operations to maintain serialization
						for (const senderKeyName of idsRequiringFetch) {
							await queueSenderKeyOperation(senderKeyName, async () => {
								logger.info({ senderKeyName }, 'fetching sender key in transaction')
								const result = await state.get(type, [senderKeyName])
								// Update transaction cache
								currentTx.cache[type] ||= {}
								Object.assign(currentTx.cache[type]!, result)
								logger.info({ senderKeyName, hasResult: !!result[senderKeyName] }, 'sender key fetch complete')
							})
						}
					} else {
						// Use runExclusive for cleaner mutex handling
						await getKeyTypeMutex(type as string).runExclusive(async () => {
							const result = await state.get(type, idsRequiringFetch)

							// Update transaction cache
							currentTx.cache[type] ||= {}
							Object.assign(currentTx.cache[type]!, result)
						})
					}
				}

				return ids.reduce((dict: { [id: string]: SignalDataTypeMap[T] }, id: string) => {
					const value = currentTx.cache[type]?.[id]
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
		set: async (data: SignalDataSet) => {
			// Track sender key updates for queue processing
			const senderKeyUpdates: string[] = []
			const currentTx = getCurrentTransaction()

			logger.error({ dataTypes: Object.keys(data), hasCurrentTx: !!currentTx }, 'SET METHOD CALLED')

			if (currentTx) {
				logger.trace({ types: Object.keys(data) }, 'caching in transaction')
				for (const key in data) {
					currentTx.cache[key] = currentTx.cache[key] || {}

					// Track sender key updates
					if (key === 'sender-key') {
						const senderKeyData = data[key]
						if (senderKeyData) {
							senderKeyUpdates.push(...Object.keys(senderKeyData))
						}
					}

					// Special handling for pre-keys and signed-pre-keys
					if (key === 'pre-key' || key === 'signed-pre-key') {
						await handlePreKeyOperations(data, key, currentTx.cache, currentTx.mutations, logger, true)
					} else {
						// Normal handling for other key types
						handleNormalKeyOperations(data, key, currentTx.cache, currentTx.mutations)
					}
				}
				
				// Process queued messages for transaction sender key updates
				for (const senderKeyName of senderKeyUpdates) {
					processQueuedMessages(senderKeyName).catch(error => {
						logger.warn({ senderKeyName, error: error.message }, 'failed to process queued messages in transaction')
					})
				}
				return
			}

			// Non-transaction path: determine mutex strategy based on data types
			const dataTypes = Object.keys(data)
			const hasSenderKeys = 'sender-key' in data
			const hasSessionOnly = dataTypes.length === 1 && dataTypes[0] === 'session'
			
			logger.trace({ dataTypes, hasSessionOnly, hasSenderKeys }, 'non-transaction storage path')
			
			try {
				// Fast path for session-only operations (critical for assertSessions)
				if (hasSessionOnly) {
					logger.trace({ sessionIds: Object.keys(data.session || {}) }, 'session-only storage')
					return await getKeyTypeMutex('session').runExclusive(async () => {
						logger.trace('executing session-only storage')
						const result = await state.set(data)
						logger.trace('session-only storage completed')
						return result
					})
				}

				// Complex path for mixed data or sender keys
				if (hasSenderKeys) {
					const senderKeyNames = Object.keys(data['sender-key'] || {})
					logger.info({ senderKeyNames, dataTypes }, 'processing mixed data with sender keys')
					
					// Handle sender key operations with per-key queues
					for (const senderKeyName of senderKeyNames) {
						await queueSenderKeyOperation(senderKeyName, async () => {
							const senderKeyData = {
								'sender-key': {
									[senderKeyName]: data['sender-key']![senderKeyName]
								}
							}

							logger.trace({ senderKeyName }, 'storing sender key')
							await state.set(senderKeyData)
							logger.trace({ senderKeyName }, 'sender key stored')
						})

						senderKeyUpdates.push(senderKeyName)
					}

					// Handle non-sender-key data
					const nonSenderKeyData = { ...data }
					delete nonSenderKeyData['sender-key']

					if (Object.keys(nonSenderKeyData).length > 0) {
						const result = await withMutexes(Object.keys(nonSenderKeyData), getKeyTypeMutex, async () => {
							// Process pre-keys with validation
							for (const keyType in nonSenderKeyData) {
								if (keyType === 'pre-key' || keyType === 'signed-pre-key') {
									await processPreKeyDeletions(nonSenderKeyData, keyType, state, logger)
								}
							}

							return await state.set(nonSenderKeyData)
						})
						
						// Process queued messages asynchronously after successful storage
						for (const senderKeyName of senderKeyUpdates) {
							processQueuedMessages(senderKeyName).catch(error => {
								logger.warn({ senderKeyName, error: error.message }, 'failed to process queued messages')
							})
						}
						
						return result
					}
				} else {
					// No sender keys - standard mutex handling
					logger.trace({ dataTypes }, 'standard storage with mutex protection')
					return await withMutexes(dataTypes, getKeyTypeMutex, async () => {
						// Process pre-keys with validation
						for (const keyType in data) {
							if (keyType === 'pre-key' || keyType === 'signed-pre-key') {
								await processPreKeyDeletions(data, keyType, state, logger)
							}
						}

						return await state.set(data)
					})
				}

			} catch (error) {
				logger.error({ dataTypes, error: error.message }, 'storage operation failed')
				throw error
			}
		},
		isInTransaction,
		...(state.clear ? { clear: state.clear } : {}),

		// Add queue management methods
		queueGroupMessage: async (
			senderKeyName: string,
			messageBytes: Uint8Array,
			originalCipher: { decrypt: (messageBytes: Uint8Array) => Promise<Uint8Array> }
		): Promise<Uint8Array> => {
			return queueMessage(senderKeyName, messageBytes, originalCipher)
		},
		async transaction<T>(work: () => Promise<T>): Promise<T> {
			return transactionMutex.acquire().then(async releaseTxMutex => {
				let result: Awaited<ReturnType<typeof work>>
				let mutexReleased = false
				
				try {
					transactionsInProgress += 1
					
					// Create new transaction state and push to stack
					const txState: TransactionState = {
						cache: {},
						mutations: {},
						dbQueries: 0
					}
					transactionStack.push(txState)
					
					if (transactionsInProgress === 1) {
						logger.trace('entering outermost transaction')
					} else {
						logger.trace({ level: transactionsInProgress }, 'entering nested transaction')
					}

					// Release the transaction mutex now that we've updated the counter
					// This allows other transactions to start preparing
					releaseTxMutex()
					mutexReleased = true

					try {
						result = await work()
						
						// commit if this is the outermost transaction
						if (transactionsInProgress === 1) {
							// Use current transaction state (may have been merged from nested transactions)
							const currentTx = getCurrentTransaction()
							const hasMutations = currentTx ? Object.keys(currentTx.mutations).length > 0 : false

							if (hasMutations && currentTx) {
								logger.error({ mutations: Object.keys(currentTx.mutations), sessionKeys: Object.keys(currentTx.mutations.session || {}) }, 'COMMITTING TRANSACTION')
								await commitWithRetry(currentTx.mutations, state, getKeyTypeMutex, maxCommitRetries, delayBetweenTriesMs, logger)
								logger.error({ dbQueries: currentTx.dbQueries }, 'TRANSACTION COMMITTED')
							} else {
								logger.trace('no mutations in outermost transaction')
							}
						} else {
							// For nested transactions, merge mutations into parent
							const parentTx = transactionStack[transactionStack.length - 2]
							if (parentTx) {
								logger.trace({ level: transactionsInProgress }, 'merging nested transaction to parent')
								// Merge cache and mutations to parent
								for (const key in txState.cache) {
									parentTx.cache[key] = parentTx.cache[key] || {}
									Object.assign(parentTx.cache[key], txState.cache[key])
								}
								for (const key in txState.mutations) {
									parentTx.mutations[key] = parentTx.mutations[key] || {}
									Object.assign(parentTx.mutations[key], txState.mutations[key])
								}
								parentTx.dbQueries += txState.dbQueries
							}
						}
					} finally {
						transactionsInProgress -= 1
						transactionStack.pop() // Remove current transaction state
					}

					return result
				} catch (error) {
					// Clean up transaction state on error
					if (transactionStack.length > 0) {
						transactionStack.pop()
					}
					
					// Only release if we haven't already released the mutex
					if (!mutexReleased) {
						releaseTxMutex()
					}
					throw error
				}
			})
		}
	}

	return storeImplementation as SignalKeyStoreWithTransaction
}

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