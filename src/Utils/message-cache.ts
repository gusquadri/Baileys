import { proto } from '../../WAProto/index.js'
import type { ILogger } from './logger'

/** Configuration for the built-in message cache */
export interface MessageCacheConfig {
	/** Maximum number of messages to cache (default: 256, following WhatsmeOW pattern) */
	maxSize?: number
	/** TTL for cached messages in milliseconds (default: 24 hours) */
	ttlMs?: number
	/** Whether to enable cache statistics logging */
	enableStats?: boolean
}

/** Statistics for cache performance monitoring */
export interface MessageCacheStats {
	hits: number
	misses: number
	evictions: number
	size: number
	hitRate: number
}

/** Internal cache entry with metadata */
interface CacheEntry {
	message: proto.IMessage
	timestamp: number
	accessCount: number
	lastAccessed: number
}

/**
 * Built-in LRU cache for sent messages following WhatsmeOW pattern
 * Handles both message storage and retrieval for retry support
 * Automatically maintains the last 256 sent messages
 */
export class MessageCache {
	private readonly cache = new Map<string, CacheEntry>()
	private readonly config: Required<MessageCacheConfig>
	private readonly logger: ILogger
	private stats: MessageCacheStats = {
		hits: 0,
		misses: 0,
		evictions: 0,
		size: 0,
		hitRate: 0
	}
	private cleanupInterval?: NodeJS.Timeout

	constructor(logger: ILogger, config: MessageCacheConfig = {}) {
		this.logger = logger
		this.config = {
			maxSize: config.maxSize || 256,
			ttlMs: config.ttlMs || 24 * 60 * 60 * 1000, // 24 hours
			enableStats: config.enableStats !== false
		}

		// Start periodic cleanup for TTL enforcement
		this.startCleanup()

		this.logger.debug({ config: this.config }, 'Built-in MessageCache initialized')
	}

	/**
	 * Store a message in the cache
	 */
	set(key: string, message: proto.IMessage): void {
		const now = Date.now()

		// Update existing entry or create new one
		const entry: CacheEntry = {
			message,
			timestamp: now,
			accessCount: this.cache.has(key) ? this.cache.get(key)!.accessCount : 0,
			lastAccessed: now
		}

		this.cache.set(key, entry)

		// Enforce size limit with LRU eviction
		if (this.cache.size > this.config.maxSize) {
			this.evictLRU()
		}

		this.updateStats()

		this.logger.trace({ key, size: this.cache.size }, 'Message cached')
	}

	/**
	 * Retrieve a message from the cache
	 */
	get(key: string): proto.IMessage | undefined {
		const entry = this.cache.get(key)

		if (!entry) {
			this.stats.misses++
			this.updateStats()
			return undefined
		}

		// Check TTL
		const now = Date.now()
		if (now - entry.timestamp > this.config.ttlMs) {
			this.cache.delete(key)
			this.stats.misses++
			this.stats.evictions++
			this.updateStats()
			this.logger.trace({ key }, 'Cache entry expired')
			return undefined
		}

		// Update access metadata for LRU
		entry.accessCount++
		entry.lastAccessed = now

		this.stats.hits++
		this.updateStats()

		this.logger.trace({ key }, 'Cache hit')
		return entry.message
	}

	/**
	 * Check if a message exists in cache
	 */
	has(key: string): boolean {
		return this.get(key) !== undefined
	}

	/**
	 * Remove a specific message from cache
	 */
	delete(key: string): boolean {
		const existed = this.cache.delete(key)
		if (existed) {
			this.updateStats()
		}
		return existed
	}

	/**
	 * Clear all cached messages
	 */
	clear(): void {
		this.cache.clear()
		this.updateStats()
		this.logger.debug('Message cache cleared')
	}

	/**
	 * Get current cache statistics
	 */
	getStats(): MessageCacheStats {
		return { ...this.stats }
	}

	/**
	 * Get cache size
	 */
	size(): number {
		return this.cache.size
	}

	/**
	 * Built-in getMessage implementation for retry support
	 * This replaces the external getMessage function entirely
	 */
	async getMessage(key: proto.IMessageKey): Promise<proto.IMessage | undefined> {
		const cacheKey = createMessageCacheKey(key)

		// Only handle messages from self (sent messages)
		if (!key.fromMe) {
			this.stats.misses++
			this.updateStats()
			this.logger.trace({ key: cacheKey }, 'Ignoring received message (not fromMe)')
			return undefined
		}

		const entry = this.cache.get(cacheKey)
		if (!entry) {
			this.stats.misses++
			this.updateStats()
			this.logger.trace({ key: cacheKey }, 'Message not found in cache')
			return undefined
		}

		// Check TTL
		const now = Date.now()
		if (now - entry.timestamp > this.config.ttlMs) {
			this.cache.delete(cacheKey)
			this.stats.misses++
			this.stats.evictions++
			this.updateStats()
			this.logger.trace({ key: cacheKey }, 'Cached message expired')
			return undefined
		}

		// Update access metadata for LRU
		entry.accessCount++
		entry.lastAccessed = now

		this.stats.hits++
		this.updateStats()

		this.logger.trace({ key: cacheKey }, 'Message retrieved from built-in cache')
		return entry.message
	}

	/**
	 * Cleanup and destroy the cache
	 */
	destroy(): void {
		if (this.cleanupInterval) {
			clearInterval(this.cleanupInterval)
			this.cleanupInterval = undefined
		}
		this.clear()
		this.logger.debug('MessageCache destroyed')
	}

	/**
	 * Evict the least recently used entry
	 */
	private evictLRU(): void {
		let oldestKey: string | null = null
		let oldestTime = Date.now()

		for (const [key, entry] of this.cache.entries()) {
			if (entry.lastAccessed < oldestTime) {
				oldestTime = entry.lastAccessed
				oldestKey = key
			}
		}

		if (oldestKey) {
			this.cache.delete(oldestKey)
			this.stats.evictions++
			this.logger.trace({ key: oldestKey }, 'LRU eviction')
		}
	}

	/**
	 * Update statistics
	 */
	private updateStats(): void {
		this.stats.size = this.cache.size
		const total = this.stats.hits + this.stats.misses
		this.stats.hitRate = total > 0 ? this.stats.hits / total : 0

		// Log stats periodically if enabled
		if (this.config.enableStats && total > 0 && total % 100 === 0) {
			this.logger.debug({ stats: this.stats }, 'Message cache statistics')
		}
	}

	/**
	 * Start periodic cleanup for TTL enforcement
	 */
	private startCleanup(): void {
		// Run cleanup every 5 minutes
		this.cleanupInterval = setInterval(() => {
			this.cleanupExpired()
		}, 5 * 60 * 1000)
	}

	/**
	 * Remove expired entries
	 */
	private cleanupExpired(): void {
		const now = Date.now()
		let cleaned = 0

		for (const [key, entry] of this.cache.entries()) {
			if (now - entry.timestamp > this.config.ttlMs) {
				this.cache.delete(key)
				cleaned++
			}
		}

		if (cleaned > 0) {
			this.stats.evictions += cleaned
			this.updateStats()
			this.logger.debug({ cleaned }, 'Cleaned expired cache entries')
		}
	}
}

/**
 * Create a message key string for caching
 */
export const createMessageCacheKey = (key: proto.IMessageKey): string => {
	return `${key.remoteJid || ''},${key.id || ''},${key.fromMe ? '1' : '0'}`
}