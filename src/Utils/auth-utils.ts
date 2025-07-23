import { AsyncLocalStorage } from 'async_hooks'
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

// Interface for the state that will be stored in AsyncLocalStorage
interface TransactionContext {
    stack: TransactionState[]
    progress: number
}

// Interface for a single transaction's state
interface TransactionState {
    cache: SignalDataSet
    mutations: SignalDataSet
    dbQueries: number
}

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
 * This has been refactored to use AsyncLocalStorage for concurrent-safe transactions.
 */
export const addTransactionCapability = (
    state: SignalKeyStore,
    logger: ILogger,
    { maxCommitRetries, delayBetweenTriesMs }: TransactionCapabilityOptions,
    messageQueueConfig: MessageQueueConfig = {
        messageTimeoutMs: 30000
    }
): SignalKeyStoreWithTransaction => {
    // Single AsyncLocalStorage to hold the context for each transaction chain.
    const transactionContext = new AsyncLocalStorage<TransactionContext>()

    // These resources are shared but are managed by mutexes, so they are safe.
    const keyTypeMutexes = new Map<string, Mutex>()
    const senderKeyMutexes = new NodeCache({ stdTTL: 1800, useClones: false, deleteOnExpire: true, maxKeys: 2000 }) as NodeCache & { get(key: string): Mutex | undefined; set(key: string, value: Mutex): void }
    const transactionMutex = new Mutex()
    const messageQueue = new Map<string, QueuedGroupMessage[]>()

    // Helper functions for mutexes and message queueing remain the same.
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

    async function queueMessage(senderKeyName: string, messageBytes: Uint8Array, originalCipher: { decrypt: (messageBytes: Uint8Array) => Promise<Uint8Array> }): Promise<Uint8Array> {
        return getSenderKeyMutex(senderKeyName).runExclusive(async () => {
            const queue = messageQueue.get(senderKeyName) || []
            return new Promise<Uint8Array>((resolve, reject) => {
                const queuedMessage: QueuedGroupMessage = { senderKeyName, messageBytes, resolve, reject, timestamp: Date.now(), originalCipher }
                queue.push(queuedMessage)
                messageQueue.set(senderKeyName, queue)
                logger.debug({ senderKeyName, queueSize: queue.length }, 'message queued for sender key')
                setTimeout(() => {
                    getSenderKeyMutex(senderKeyName).runExclusive(async () => {
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
                    }).catch(() => {})
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

    // These now get their state from the AsyncLocalStorage context
    const getCurrentTransaction = (): TransactionState | null => {
        const store = transactionContext.getStore()
        return store && store.stack.length > 0 ? store.stack[store.stack.length - 1] : null
    }

    const isInTransaction = () => {
        const store = transactionContext.getStore()
        return !!store && store.progress > 0
    }

    const storeImplementation = {
        get: async <T extends keyof SignalDataTypeMap>(type: T, ids: string[]) => {
            const currentTx = getCurrentTransaction()
            if (currentTx) {
                const dict = currentTx.cache[type]
                const idsRequiringFetch = dict ? ids.filter(item => typeof dict[item] === 'undefined') : ids
                if (idsRequiringFetch.length) {
                    currentTx.dbQueries += 1
                    if (type === 'sender-key') {
                        logger.info({ idsRequiringFetch }, 'processing sender keys in transaction')
                        for (const senderKeyName of idsRequiringFetch) {
                            await queueSenderKeyOperation(senderKeyName, async () => {
                                logger.info({ senderKeyName }, 'fetching sender key in transaction')
                                const result = await state.get(type, [senderKeyName])
                                currentTx.cache[type] ||= {}
                                Object.assign(currentTx.cache[type]!, result)
                                logger.info({ senderKeyName, hasResult: !!result[senderKeyName] }, 'sender key fetch complete')
                            })
                        }
                    } else {
                        await getKeyTypeMutex(type as string).runExclusive(async () => {
                            const result = await state.get(type, idsRequiringFetch)
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
                if (type === 'sender-key') {
                    const results: { [key: string]: SignalDataTypeMap[typeof type] } = {}
                    for (const senderKeyName of ids) {
                        const result = await queueSenderKeyOperation(senderKeyName, async () => await state.get(type, [senderKeyName]))
                        Object.assign(results, result)
                    }
                    return results
                } else {
                    return await getKeyTypeMutex(type as string).runExclusive(() => state.get(type, ids))
                }
            }
        },
        set: async (data: SignalDataSet) => {
            const senderKeyUpdates: string[] = []
            const currentTx = getCurrentTransaction()
            if (currentTx) {
                logger.trace({ types: Object.keys(data) }, 'caching in transaction')
                for (const key in data) {
                    currentTx.cache[key] = currentTx.cache[key] || {}
                    if (key === 'sender-key') {
                        const senderKeyData = data[key]
                        if (senderKeyData) {
                            senderKeyUpdates.push(...Object.keys(senderKeyData))
                        }
                    }
                    if (key === 'pre-key' || key === 'signed-pre-key') {
                        await handlePreKeyOperations(data, key, currentTx.cache, currentTx.mutations, logger, true)
                    } else {
                        handleNormalKeyOperations(data, key, currentTx.cache, currentTx.mutations)
                    }
                }
                for (const senderKeyName of senderKeyUpdates) {
                    processQueuedMessages(senderKeyName).catch(error => {
                        logger.warn({ senderKeyName, error: error.message }, 'failed to process queued messages in transaction')
                    })
                }
                return
            }
            const dataTypes = Object.keys(data)
            const hasSenderKeys = 'sender-key' in data
            const hasSessionOnly = dataTypes.length === 1 && dataTypes[0] === 'session'
            try {
                if (hasSessionOnly) {
                    logger.trace({ sessionIds: Object.keys(data.session || {}) }, 'session-only storage')
                    return await getKeyTypeMutex('session').runExclusive(async () => {
                        return await state.set(data)
                    })
                }
                if (hasSenderKeys) {
                    const senderKeyNames = Object.keys(data['sender-key'] || {})
                    logger.info({ senderKeyNames, dataTypes }, 'processing mixed data with sender keys')
                    for (const senderKeyName of senderKeyNames) {
                        await queueSenderKeyOperation(senderKeyName, async () => {
                            const senderKeyData = { 'sender-key': { [senderKeyName]: data['sender-key']![senderKeyName] } }
                            logger.trace({ senderKeyName }, 'storing sender key')
                            await state.set(senderKeyData)
                            logger.trace({ senderKeyName }, 'sender key stored')
                        })
                        senderKeyUpdates.push(senderKeyName)
                    }
                    const nonSenderKeyData = { ...data }
                    delete nonSenderKeyData['sender-key']
                    if (Object.keys(nonSenderKeyData).length > 0) {
                        const result = await withMutexes(Object.keys(nonSenderKeyData), getKeyTypeMutex, async () => {
                            for (const keyType in nonSenderKeyData) {
                                if (keyType === 'pre-key' || keyType === 'signed-pre-key') {
                                    await processPreKeyDeletions(nonSenderKeyData, keyType, state, logger)
                                }
                            }
                            return await state.set(nonSenderKeyData)
                        })
                        for (const senderKeyName of senderKeyUpdates) {
                            processQueuedMessages(senderKeyName).catch(error => {
                                logger.warn({ senderKeyName, error: error.message }, 'failed to process queued messages')
                            })
                        }
                        return result
                    }
                } else {
                    logger.trace({ dataTypes }, 'standard storage with mutex protection')
                    return await withMutexes(dataTypes, getKeyTypeMutex, async () => {
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
        queueGroupMessage: async (senderKeyName: string, messageBytes: Uint8Array, originalCipher: { decrypt: (messageBytes: Uint8Array) => Promise<Uint8Array> }): Promise<Uint8Array> => {
            return queueMessage(senderKeyName, messageBytes, originalCipher)
        },
        // This is the main refactored function
        async transaction<T>(work: () => Promise<T>): Promise<T> {
            const store = transactionContext.getStore()
            if (store) {
                // Already in a transaction, just execute the logic.
                // The mutex is already held by the parent.
                return await this.runTransactionLogic(work)
            } else {
                // This is the outermost transaction. It's responsible for acquiring and releasing the lock.
                const releaseTxMutex = await transactionMutex.acquire()
                try {
                    // Start a new context and run the logic within it.
                    return await transactionContext.run({ stack: [], progress: 0 }, () => {
                        return this.runTransactionLogic(work)
                    })
                } finally {
                    // Release the lock ONLY after the entire transaction chain (including commit) is done.
                    releaseTxMutex()
                }
            }
        },
        // Extracted the core transaction logic to be reusable
        async runTransactionLogic<T>(work: () => Promise<T>): Promise<T> {
            const context = transactionContext.getStore()! // We are guaranteed to be in a context here

            context.progress += 1
            const txState: TransactionState = { cache: {}, mutations: {}, dbQueries: 0 }
            context.stack.push(txState)

            if (context.progress === 1) {
                logger.trace('entering outermost transaction')
            } else {
                logger.trace({ level: context.progress }, 'entering nested transaction')
            }

            try {
                const result = await work()

                // The commit logic only runs when the outermost transaction is finishing.
                if (context.progress === 1) {
                    const hasMutations = Object.keys(txState.mutations).length > 0
                    if (hasMutations) {
                        logger.trace('committing outermost transaction')
                        await commitWithRetry(txState.mutations, state, getKeyTypeMutex, maxCommitRetries, delayBetweenTriesMs, logger)
                        logger.trace({ dbQueries: txState.dbQueries }, 'transaction completed')
                    } else {
                        logger.trace('no mutations in outermost transaction')
                    }
                } else {
                    // For nested transactions, merge mutations into the parent.
                    const parentTx = context.stack[context.stack.length - 2]
                    if (parentTx) {
                        logger.trace({ level: context.progress }, 'merging nested transaction to parent')
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
                return result
            } finally {
                context.progress -= 1
                context.stack.pop()
            }
        }
    }

    return storeImplementation as SignalKeyStoreWithTransaction
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
