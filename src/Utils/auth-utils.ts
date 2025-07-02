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

	function getUniqueId(type: string, id: string) {
		return `${type}.${id}`
	}

	return {
		async get(type, ids) {
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
		},
		async set(data) {
			let keys = 0
			for (const type in data) {
				for (const id in data[type]) {
					cache.set(getUniqueId(type, id), data[type][id])
					keys += 1
				}
			}

			logger?.trace({ keys }, 'updated cache')

			await store.set(data)
		},
		async clear() {
			cache.flushAll()
			await store.clear?.()
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
	// Global transaction mutex
	const transactionMutex = new Mutex()

	// number of queries made to the DB during the transaction
	// only there for logging purposes
	let dbQueriesInTransaction = 0
	let transactionCache: SignalDataSet = {}
	let mutations: SignalDataSet = {}

	let transactionsInProgress = 0

	// Helper function to handle pre-key deletion in transaction
	function handlePreKeyDeletion(
		keyId: string,
		transactionCache: SignalDataSet,
		mutations: SignalDataSet,
		logger: ILogger
	): boolean {
		// Only allow deletion if we have the key in cache
		const preKeyCache = transactionCache['pre-key']
		if (preKeyCache?.[keyId]) {
			// Ensure pre-key cache exists
			if (!transactionCache['pre-key']) {
				transactionCache['pre-key'] = {}
			}

			transactionCache['pre-key'][keyId] = null

			if (!mutations['pre-key']) {
				mutations['pre-key'] = {}
			}

			mutations['pre-key'][keyId] = null
			return true
		} else {
			// Skip deletion if key doesn't exist in cache
			logger.warn(`Attempted to delete non-existent pre-key: ${keyId}`)
			return false
		}
	}

	// Helper function to handle pre-key update in transaction
	function handlePreKeyUpdate(
		keyId: string,
		value: SignalDataTypeMap['pre-key'],
		transactionCache: SignalDataSet,
		mutations: SignalDataSet
	) {
		if (!transactionCache['pre-key']) {
			transactionCache['pre-key'] = {}
		}

		transactionCache['pre-key'][keyId] = value

		if (!mutations['pre-key']) {
			mutations['pre-key'] = {}
		}

		mutations['pre-key'][keyId] = value
	}

	// Helper function to process pre-key data in transaction
	function processPreKeyDataInTransaction(
		data: SignalDataSet,
		transactionCache: SignalDataSet,
		mutations: SignalDataSet,
		logger: ILogger
	) {
		const preKeyData = data['pre-key']
		if (!preKeyData) return

		for (const keyId in preKeyData) {
			// If we're trying to delete a pre-key, check if we have it in cache first
			if (preKeyData[keyId] === null) {
				handlePreKeyDeletion(keyId, transactionCache, mutations, logger)
			} else {
				// Normal update
				handlePreKeyUpdate(keyId, preKeyData[keyId], transactionCache, mutations)
			}
		}
	}

	// Helper function to process non-pre-key data in transaction
	function processNormalKeyDataInTransaction(
		key: string,
		data: SignalDataSet,
		transactionCache: SignalDataSet,
		mutations: SignalDataSet
	) {
		const keyData = data[key]
		if (!keyData) return

		if (!transactionCache[key]) {
			transactionCache[key] = {}
		}

		Object.assign(transactionCache[key], keyData)

		if (!mutations[key]) {
			mutations[key] = {}
		}

		Object.assign(mutations[key], keyData)
	}

	// Helper function to handle pre-key validation outside transaction
	async function validatePreKeyDeletion(keyId: string, data: SignalDataSet, state: SignalKeyStore, logger: ILogger) {
		// Check if the key exists before deleting
		const existingKeys = await state.get('pre-key', [keyId])
		if (!existingKeys[keyId]) {
			// Skip deletion if key doesn't exist
			logger.warn(`Attempted to delete non-existent pre-key: ${keyId}`)
			const preKeyData = data['pre-key']
			if (preKeyData) {
				delete preKeyData[keyId]
			}
		}
	}

	// Helper function to process pre-keys outside transaction
	async function processPreKeysOutsideTransaction(data: SignalDataSet, state: SignalKeyStore, logger: ILogger) {
		const preKeyData = data['pre-key']
		if (!preKeyData) return

		for (const keyId in preKeyData) {
			if (preKeyData[keyId] === null) {
				await validatePreKeyDeletion(keyId, data, state, logger)
			}
		}
	}

	// Helper function to acquire mutexes for key types in deterministic order to prevent deadlocks
	async function acquireMutexesForKeyTypes(data: SignalDataSet): Promise<Mutex[]> {
		// Sort key types to ensure consistent ordering and prevent deadlocks
		const sortedKeyTypes = Object.keys(data).sort()
		const mutexes: Mutex[] = []

		for (const keyType of sortedKeyTypes) {
			const typeMutex = getKeyTypeMutex(keyType)
			await typeMutex.acquire()
			mutexes.push(typeMutex)
		}

		return mutexes
	}

	// Helper function to release mutexes
	function releaseMutexes(mutexes: Mutex[]) {
		while (mutexes.length > 0) {
			const mutex = mutexes.pop()
			if (mutex) mutex.release()
		}
	}

	// Helper function to attempt commit with retry logic
	async function attemptCommitWithRetry(
		mutations: SignalDataSet,
		state: SignalKeyStore,
		maxRetries: number,
		delayMs: number,
		logger: ILogger
	): Promise<void> {
		let tries = maxRetries

		while (tries > 0) {
			tries -= 1

			try {
				// Acquire mutexes for all key types being modified
				const mutexes = await acquireMutexesForKeyTypes(mutations)
				try {
					await state.set(mutations)
					logger.trace({ dbQueriesInTransaction }, 'committed transaction')
					return // Success, exit the retry loop
				} finally {
					releaseMutexes(mutexes)
				}
			} catch (error) {
				logger.warn(`failed to commit ${Object.keys(mutations).length} mutations, tries left=${tries}`)
				if (tries > 0) {
					await delay(delayMs)
				} else {
					throw error // Re-throw on final attempt
				}
			}
		}
	}

	return {
		get: async (type, ids) => {
			if (isInTransaction()) {
				const dict = transactionCache[type]
				const idsRequiringFetch = dict ? ids.filter(item => typeof dict[item] === 'undefined') : ids
				// only fetch if there are any items to fetch
				if (idsRequiringFetch.length) {
					dbQueriesInTransaction += 1

					// Acquire mutex for this key type to prevent concurrent access
					const typeMutex = getKeyTypeMutex(type as string)
					await typeMutex.acquire()

					try {
						const result = await state.get(type, idsRequiringFetch)

						// Update transaction cache
						transactionCache[type] ||= {}
						Object.assign(transactionCache[type]!, result)
					} finally {
						typeMutex.release()
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
				// Not in transaction, fetch directly with mutex protection
				const typeMutex = getKeyTypeMutex(type as string)
				return await typeMutex.acquire().then(async release => {
					try {
						return await state.get(type, ids)
					} finally {
						release()
					}
				})
			}
		},
		set: async data => {
			if (isInTransaction()) {
				logger.trace({ types: Object.keys(data) }, 'caching in transaction')
				for (const key in data) {
					transactionCache[key] = transactionCache[key] || {}

					// Special handling for pre-keys to prevent unexpected deletion
					if (key === 'pre-key') {
						processPreKeyDataInTransaction(data, transactionCache, mutations, logger)
					} else {
						// Normal handling for other key types
						processNormalKeyDataInTransaction(key, data, transactionCache, mutations)
					}
				}
			} else {
				// Not in transaction, apply directly with mutex protection
				const mutexes: Mutex[] = []

				try {
					// Sort key types to ensure consistent ordering and prevent deadlocks
					const sortedKeyTypes = Object.keys(data).sort()

					// Acquire all necessary mutexes to prevent concurrent access
					for (const keyType of sortedKeyTypes) {
						const typeMutex = getKeyTypeMutex(keyType)
						await typeMutex.acquire()
						mutexes.push(typeMutex)

						// For pre-keys, we need special handling
						if (keyType === 'pre-key') {
							await processPreKeysOutsideTransaction(data, state, logger)
						}
					}

					// Apply changes to the store
					await state.set(data)
				} finally {
					releaseMutexes(mutexes)
				}
			}
		},
		isInTransaction,
		...(state.clear ? { clear: state.clear } : {}),
		async transaction(work) {
			// Use the transaction mutex to ensure only one transaction at a time
			return transactionMutex.acquire().then(async releaseTxMutex => {
				let result: Awaited<ReturnType<typeof work>>
				try {
					transactionsInProgress += 1
					if (transactionsInProgress === 1) {
						logger.trace('entering transaction')
					}

					// Execute the transaction work while holding the mutex
					result = await work()

					// commit if this is the outermost transaction
					if (transactionsInProgress === 1) {
						if (Object.keys(mutations).length) {
							logger.trace('committing transaction')
							// retry mechanism to ensure we've some recovery
							// in case a transaction fails in the first attempt
							await attemptCommitWithRetry(mutations, state, maxCommitRetries, delayBetweenTriesMs, logger)
						} else {
							logger.trace('no mutations in transaction')
						}
					}

					return result
				} catch (error) {
					throw error
				} finally {
					transactionsInProgress -= 1
					if (transactionsInProgress === 0) {
						transactionCache = {}
						mutations = {}
						dbQueriesInTransaction = 0
					}

					// Always release the transaction mutex
					releaseTxMutex()
				}
			})
		}
	}

	// Get or create a mutex for a specific key typeAdd commentMore actions
	function getKeyTypeMutex(type: string): Mutex {
		let mutex = keyTypeMutexes.get(type)
		if (!mutex) {
			mutex = new Mutex()
			keyTypeMutexes.set(type, mutex)
		}

		return mutex
	}

	// Check if we are currently in a transaction
	function isInTransaction() {
		return transactionsInProgress > 0
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
