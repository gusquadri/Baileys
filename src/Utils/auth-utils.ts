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
						handlePreKeyInTransaction(key, data[key], transactionCache, mutations, logger)
					} else {
						// Normal handling for other key types
						Object.assign(transactionCache[key], data[key])

						mutations[key] = mutations[key] || {}
						Object.assign(mutations[key], data[key])
					}
				}
			} else {
				// Not in transaction, apply directly with mutex protection
				const mutexes: Mutex[] = []

				try {
					// Acquire all necessary mutexes to prevent concurrent access
					const sortedKeyTypes = Object.keys(data).sort()
					for (const keyType of sortedKeyTypes) {
						const typeMutex = getKeyTypeMutex(keyType)
						await typeMutex.acquire()
						mutexes.push(typeMutex)

						// For pre-keys, we need special handling
						if (keyType === 'pre-key') {
							await handlePreKeyOutsideTransaction(keyType, data[keyType], state, logger)
						}
					}

					// Apply changes to the store
					await state.set(data)
				} finally {
					// Release all mutexes in reverse order
					while (mutexes.length > 0) {
						const mutex = mutexes.pop()
						if (mutex) mutex.release()
					}
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

					try {
						result = await work()
						// commit if this is the outermost transaction
						if (transactionsInProgress === 1) {
							if (Object.keys(mutations).length) {
								logger.trace('committing transaction')
								await commitMutationsWithRetry(
									mutations,
									state,
									logger,
									maxCommitRetries,
									delayBetweenTriesMs,
									getKeyTypeMutex,
									dbQueriesInTransaction
								)
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
				} finally {
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

	// Helper function to handle pre-key operations in transaction
	function handlePreKeyInTransaction(
		key: string,
		keyData: any,
		transactionCache: SignalDataSet,
		mutations: SignalDataSet,
		logger: ILogger
	) {
		for (const keyId in keyData) {
			const keyValue = keyData[keyId]
			if (keyValue === null) {
				handlePreKeyDeletion(key, keyId, transactionCache, mutations, logger)
			} else {
				handlePreKeyUpdate(key, keyId, keyValue, transactionCache, mutations)
			}
		}
	}

	// Helper function to handle pre-key deletion
	function handlePreKeyDeletion(
		key: string,
		keyId: string,
		transactionCache: SignalDataSet,
		mutations: SignalDataSet,
		logger: ILogger
	) {
		if (!transactionCache[key]?.[keyId]) {
			logger.warn(`Attempted to delete non-existent pre-key: ${keyId}`)
			return
		}

		if (!transactionCache[key]) {
			transactionCache[key] = {}
		}

		transactionCache[key][keyId] = null

		if (!mutations[key]) {
			mutations[key] = {}
		}

		mutations[key][keyId] = null
	}

	// Helper function to handle pre-key update
	function handlePreKeyUpdate(
		key: string,
		keyId: string,
		keyValue: any,
		transactionCache: SignalDataSet,
		mutations: SignalDataSet
	) {
		if (!transactionCache[key]) {
			transactionCache[key] = {}
		}

		transactionCache[key][keyId] = keyValue

		if (!mutations[key]) {
			mutations[key] = {}
		}

		mutations[key][keyId] = keyValue
	}

	// Helper function to handle pre-key operations outside transaction
	async function handlePreKeyOutsideTransaction(keyType: string, keyData: any, state: SignalKeyStore, logger: ILogger) {
		for (const keyId in keyData) {
			if (keyData[keyId] === null) {
				const existingKeys = await state.get(keyType as any, [keyId])
				if (!existingKeys[keyId]) {
					logger.warn(`Attempted to delete non-existent pre-key: ${keyId}`)
					delete keyData[keyId]
				}
			}
		}
	}

	// Helper function to commit mutations with retry logic
	async function commitMutationsWithRetry(
		mutations: SignalDataSet,
		state: SignalKeyStore,
		logger: ILogger,
		maxRetries: number,
		delayMs: number,
		getKeyTypeMutex: (type: string) => Mutex,
		dbQueriesInTransaction: number
	): Promise<void> {
		let tries = maxRetries
		while (tries) {
			tries -= 1
			try {
				await commitMutationsOnce(mutations, state, logger, getKeyTypeMutex, dbQueriesInTransaction)
				break
			} catch (error) {
				logger.warn(`failed to commit ${Object.keys(mutations).length} mutations, tries left=${tries}`)
				await delay(delayMs)
			}
		}
	}

	// Helper function to commit mutations once
	async function commitMutationsOnce(
		mutations: SignalDataSet,
		state: SignalKeyStore,
		logger: ILogger,
		getKeyTypeMutex: (type: string) => Mutex,
		dbQueriesInTransaction: number
	): Promise<void> {
		const mutexes: Mutex[] = []
		const sortedKeyTypes = Object.keys(mutations).sort()
		for (const keyType of sortedKeyTypes) {
			const typeMutex = getKeyTypeMutex(keyType)
			await typeMutex.acquire()
			mutexes.push(typeMutex)
		}

		try {
			await state.set(mutations)
			logger.trace({ dbQueriesInTransaction }, 'committed transaction')
		} finally {
			while (mutexes.length > 0) {
				const mutex = mutexes.pop()
				if (mutex) mutex.release()
			}
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
