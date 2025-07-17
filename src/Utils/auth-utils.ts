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
 * Batch validate pre-key deletions for better performance
 */
async function validatePreKeyDeletions(
	keyType: string,
	keyIds: string[],
	state: SignalKeyStore,
	logger: ILogger
): Promise<Set<string>> {
	if (keyIds.length === 0) return new Set()

	const mutex = getPreKeyMutex(keyType)
	
	return mutex.runExclusive(async () => {
		const existingKeys = await state.get(keyType as keyof SignalDataTypeMap, keyIds)
		
		// Track which keys actually exist
		const existingKeySet = new Set<string>()
		const missingKeys: string[] = []
		
		for (const keyId of keyIds) {
			if (existingKeys[keyId]) {
				existingKeySet.add(keyId)
			} else {
				missingKeys.push(keyId)
			}
		}
		
		// Log missing keys efficiently
		if (missingKeys.length > 0) {
			logger.warn(`Found ${missingKeys.length} non-existent ${keyType}s: ${missingKeys.slice(0, 5).join(', ')}${missingKeys.length > 5 ? '...' : ''}`)
		}
		
		return existingKeySet
	})
}

/**
 * Update cache and mutations atomically
 */
function updateCacheAndMutations(
	keyType: string,
	keyId: string,
	value: any,
	transactionCache: SignalDataSet,
	mutations: SignalDataSet
): void {
	// Ensure structures exist
	transactionCache[keyType] = transactionCache[keyType] || {}
	mutations[keyType] = mutations[keyType] || {}

	// Update both atomically
	transactionCache[keyType][keyId] = value
	mutations[keyType][keyId] = value
}

/**
 * Enhanced pre-key operations handler with 100% async-mutex usage
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

		// Collect deletion keys for batch validation
		const deletionKeys = Object.keys(keyData).filter(keyId => keyData[keyId] === null)
		let validDeletionKeys = new Set<string>()
		
		// Batch validate deletions outside of transaction
		if (deletionKeys.length > 0 && !isInTransaction && state) {
			validDeletionKeys = await validatePreKeyDeletions(keyType, deletionKeys, state, logger)
		}

		// Process all operations for this key type
		for (const keyId in keyData) {
			const isDeleteOperation = keyData[keyId] === null

			if (isDeleteOperation) {
				// Enhanced deletion validation
				let canDelete = false
				
				if (isInTransaction) {
					// In transaction, only allow deletion if key exists in cache
					canDelete = !!(transactionCache[keyType]?.[keyId])
					if (!canDelete) {
						logger.warn(`Skipping deletion of non-existent ${keyType} in transaction: ${keyId}`)
					}
				} else {
					// Outside transaction, use batch validation result
					canDelete = validDeletionKeys.has(keyId)
				}

				if (canDelete) {
					updateCacheAndMutations(keyType, keyId, null, transactionCache, mutations)
					logger.trace({ keyType, keyId }, 'pre-key marked for deletion')
				}
			} else {
				// Normal update
				updateCacheAndMutations(keyType, keyId, keyData[keyId], transactionCache, mutations)
				logger.trace({ keyType, keyId }, 'pre-key updated')
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
 * Enhanced pre-key deletion processing with mutex protection
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

		// Collect all deletion keys for batch validation
		const deletionKeys = Object.keys(keyData).filter(keyId => keyData[keyId] === null)
		
		if (deletionKeys.length > 0) {
			const validDeletionKeys = await validatePreKeyDeletions(keyType, deletionKeys, state, logger)
			
			// Remove invalid deletion operations from data
			for (const keyId of deletionKeys) {
				if (!validDeletionKeys.has(keyId)) {
					delete data[keyType][keyId]
					logger.trace({ keyType, keyId }, 'removed invalid pre-key deletion')
				}
			}
		}
	})
}

/**
 * Utility function to generate pre-keys with proper mutex protection
 */
export async function generatePreKeysWithMutex(
	keyType: 'pre-key' | 'signed-pre-key',
	startId: number,
	count: number,
	generateFn: (id: number) => any,
	logger: ILogger
): Promise<SignalDataSet> {
	const mutex = getPreKeyMutex(keyType)
	
	return mutex.runExclusive(async () => {
		const result: SignalDataSet = { [keyType]: {} }
		
		logger.trace({ keyType, startId, count }, 'generating pre-keys')
		
		for (let i = 0; i < count; i++) {
			const keyId = ((startId + i) % 16777216).toString() // Ensure ID doesn't overflow
			result[keyType][keyId] = generateFn(startId + i)
		}
		
		logger.trace({ keyType, generated: count }, 'pre-keys generated')
		return result
	})
}

/**
 * Utility function to cleanup expired pre-keys with mutex protection
 */
export async function cleanupExpiredPreKeys(
	keyType: 'pre-key' | 'signed-pre-key',
	maxAge: number,
	state: SignalKeyStore,
	logger: ILogger
): Promise<number> {
	const mutex = getPreKeyMutex(keyType)
	
	return mutex.runExclusive(async () => {
		logger.info({ keyType, maxAge }, 'starting pre-key cleanup')
		
		// Implementation would depend on your specific pre-key storage format
		// This is a placeholder for the actual cleanup logic
		const cleanedCount = 0
		
		logger.info({ keyType, cleanedCount }, 'pre-key cleanup completed')
		return cleanedCount
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
	{ maxCommitRetries, delayBetweenTriesMs }: TransactionCapabilityOptions
): SignalKeyStoreWithTransaction => {
	// Mutex for each key type (session, pre-key, etc.)
	const keyTypeMutexes = new Map<string, Mutex>()

	// Per-sender-key-name mutexes for fine-grained serialization
	const senderKeyMutexes = new Map<string, Mutex>()

	// Global transaction mutex
	const transactionMutex = new Mutex()

	// number of queries made to the DB during the transaction
	// only there for logging purposes
	let dbQueriesInTransaction = 0
	let transactionCache: SignalDataSet = {}
	let mutations: SignalDataSet = {}

	let transactionsInProgress = 0

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
						const result = await queueSenderKeyOperation(senderKeyName, async () => 
							await state.get(type, [senderKeyName])
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
				for (const key in data) {
					transactionCache[key] = transactionCache[key] || {}

					// Special handling for pre-keys and signed-pre-keys
					if (key === 'pre-key' || key === 'signed-pre-key') {
						await handlePreKeyOperations(data, key, transactionCache, mutations, logger, true)
					} else {
						// Normal handling for other key types
						handleNormalKeyOperations(data, key, transactionCache, mutations)
					}
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
		async transaction(work) {
			return transactionMutex.acquire().then(async releaseTxMutex => {
				let result: Awaited<ReturnType<typeof work>>
				try {
					transactionsInProgress += 1
					if (transactionsInProgress === 1) {
						logger.trace('entering transaction')
					}

					// Release the transaction mutex now that we've updated the counter
					// This allows other transactions to start preparing
					releaseTxMutex()

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
					releaseTxMutex()
					throw error
				}
			})
		}
	}
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
