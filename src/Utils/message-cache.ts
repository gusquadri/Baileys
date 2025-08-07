import { proto } from '../../WAProto/index.js'
import type { ILogger } from './logger'

// Number of sent messages to cache in memory for handling retry receipts (following whatsmeow)
const recentMessagesSize = 256

/** Simple message cache configuration */
export interface MessageCacheConfig {
	/** Maximum number of messages to cache (default: 256, following whatsmeow) */
	maxSize?: number
}

/** Basic cache statistics */
export interface MessageCacheStats {
	hits: number
	misses: number
	size: number
	hitRate: number
}

/** Recent message key (following whatsmeow pattern) */
interface RecentMessageKey {
	remoteJid: string
	id: string
}

/** Recent message entry */
interface RecentMessage {
	message: proto.IMessage
}

/**
 * Simple message cache following whatsmeow's circular buffer approach
 * Maintains the last 256 sent messages for handling retry receipts
 */
export class MessageCache {
	private readonly recentMessagesMap = new Map<string, RecentMessage>()
	private readonly recentMessagesList: RecentMessageKey[] = new Array(recentMessagesSize).fill(null).map(() => ({ remoteJid: '', id: '' }))
	private recentMessagesPtr = 0
	private readonly maxSize: number
	private readonly logger: ILogger
	
	// Simple statistics
	private hits = 0
	private misses = 0

	constructor(logger: ILogger, config: MessageCacheConfig = {}) {
		this.logger = logger
		this.maxSize = config.maxSize || recentMessagesSize
		
		this.logger.debug({ maxSize: this.maxSize }, 'MessageCache initialized following whatsmeow pattern')
	}

	/**
	 * Add a recent message to the cache (following whatsmeow's addRecentMessage)
	 */
	addRecentMessage(remoteJid: string, id: string, message: proto.IMessage): void {
		const key = this.createKey(remoteJid, id)
		
		// If we're about to overwrite an entry, remove it from the map first
		const oldKey = this.recentMessagesList[this.recentMessagesPtr]
		if (oldKey && oldKey.id !== '') {
			this.recentMessagesMap.delete(this.createKey(oldKey.remoteJid, oldKey.id))
		}
		
		// Add new message
		this.recentMessagesMap.set(key, { message })
		this.recentMessagesList[this.recentMessagesPtr] = { remoteJid, id }
		
		// Advance pointer (circular buffer)
		this.recentMessagesPtr++
		if (this.recentMessagesPtr >= this.maxSize) {
			this.recentMessagesPtr = 0
		}
		
		this.logger.trace({ remoteJid, id, size: this.recentMessagesMap.size }, 'Message added to cache')
	}

	/**
	 * Get a recent message from the cache (following whatsmeow's getRecentMessage)
	 */
	getRecentMessage(remoteJid: string, id: string): proto.IMessage | undefined {
		const key = this.createKey(remoteJid, id)
		const entry = this.recentMessagesMap.get(key)
		
		if (entry) {
			this.hits++
			this.logger.trace({ remoteJid, id }, 'Cache hit')
			return entry.message
		} else {
			this.misses++
			this.logger.trace({ remoteJid, id }, 'Cache miss')
			return undefined
		}
	}

	/**
	 * Get current cache statistics
	 */
	getStats(): MessageCacheStats {
		const total = this.hits + this.misses
		return {
			hits: this.hits,
			misses: this.misses,
			size: this.recentMessagesMap.size,
			hitRate: total > 0 ? this.hits / total : 0
		}
	}

	/**
	 * Get cache size
	 */
	size(): number {
		return this.recentMessagesMap.size
	}

	/**
	 * Clear all cached messages
	 */
	clear(): void {
		this.recentMessagesMap.clear()
		this.recentMessagesList.fill({ remoteJid: '', id: '' })
		this.recentMessagesPtr = 0
		this.hits = 0
		this.misses = 0
		this.logger.debug('Message cache cleared')
	}

	/**
	 * Built-in getMessage implementation for retry support
	 * Simple implementation that only handles sent messages
	 */
	async getMessage(key: proto.IMessageKey): Promise<proto.IMessage | undefined> {
		if (!key) {
			return undefined
		}

		const remoteJid = key.remoteJid || ''
		const id = key.id || ''
		
		const message = this.getRecentMessage(remoteJid, id)
		return message
	}

	/**
	 * Simple cleanup - just clear the cache
	 */
	destroy(): void {
		this.clear()
		this.logger.debug('MessageCache destroyed')
	}

	/**
	 * Create a simple cache key from remoteJid and id
	 */
	private createKey(remoteJid: string, id: string): string {
		return `${remoteJid}:${id}`
	}

}

/**
 * Create a simple message cache key for backward compatibility
 */
export const createMessageCacheKey = (key: proto.IMessageKey): string => {
	const remoteJid = key.remoteJid || ''
	const id = key.id || ''
	return `${remoteJid}:${id}`
}