import { SignalAuthState } from '../Types'
import { BaileysEventEmitter } from '../Types'
import { jidDecode } from '../WABinary'
import { requestNewSession } from './session-manager'

interface KeySyncConfig {
	healthCheckInterval: number // milliseconds
	staleKeyThreshold: number // milliseconds
	maxConcurrentRefresh: number
	enableProactiveSync: boolean
}

interface KeySyncMetadata {
	lastSync: number
	failureCount: number
	nextRetry: number
}

interface SessionHealthInfo {
	isStale: boolean
	lastActivity: number
	messageCount: number
}

interface KeyStoreStats {
	totalSessions: number
	totalPreKeys: number
	totalSenderKeys: number
	staleSessions: number
	keyMetadataEntries: number
}

const DEFAULT_CONFIG: KeySyncConfig = {
	healthCheckInterval: 5 * 60 * 1000, // 5 minutes
	staleKeyThreshold: 24 * 60 * 60 * 1000, // 24 hours
	maxConcurrentRefresh: 3,
	enableProactiveSync: true
}

const MAX_RETRY_ATTEMPTS = 5
const INITIAL_RETRY_DELAY = 1000
const RETRY_MULTIPLIER = 2

export class KeySyncManager {
	private config: KeySyncConfig
	private healthCheckInterval?: NodeJS.Timeout
	private refreshQueue: Set<string> = new Set()
	private isRefreshing = false
	private keyMetadata = new Map<string, KeySyncMetadata>()

	constructor(
		private auth: SignalAuthState,
		private eventEmitter: BaileysEventEmitter,
		private socket?: any,
		config?: Partial<KeySyncConfig>
	) {
		this.config = { ...DEFAULT_CONFIG, ...config }
	}

	private jidToSessionId(jid: string): string {
		const decoded = jidDecode(jid)
		if (!decoded) {
			throw new Error(`Failed to decode invalid JID: ${jid}`)
		}
		const { user, device } = decoded
		return `${user}:${device || 0}`
	}

	start() {
		if (!this.config.enableProactiveSync) {
			return
		}

		this.healthCheckInterval = setInterval(() => {
			this.performHealthCheck().catch(error => {
				console.error('Key health check failed:', error)
			})
		}, this.config.healthCheckInterval)

		console.log('Key sync manager started')
	}

	stop() {
		if (this.healthCheckInterval) {
			clearInterval(this.healthCheckInterval)
			this.healthCheckInterval = undefined
		}
		console.log('Key sync manager stopped')
	}

	private async checkKeyFreshness(sessionId: string): Promise<SessionHealthInfo> {
		const { [sessionId]: session } = await this.auth.keys.get('session', [sessionId])
		const metadata = this.keyMetadata.get(sessionId)
		
		const now = Date.now()
		const lastActivity = metadata?.lastSync || 0
		const isStale = session && (now - lastActivity > this.config.staleKeyThreshold)
		
		return {
			isStale,
			lastActivity,
			messageCount: 0
		}
	}

	private updateKeyMetadata(sessionId: string, success: boolean) {
		const metadata = this.keyMetadata.get(sessionId) || {
			lastSync: 0,
			failureCount: 0,
			nextRetry: 0
		}
		
		if (success) {
			metadata.lastSync = Date.now()
			metadata.failureCount = 0
			metadata.nextRetry = 0
		} else {
			metadata.failureCount++
			const delay = INITIAL_RETRY_DELAY * Math.pow(RETRY_MULTIPLIER, Math.min(metadata.failureCount - 1, 5))
			metadata.nextRetry = Date.now() + delay
		}
		
		this.keyMetadata.set(sessionId, metadata)
	}

	private shouldRetry(sessionId: string): boolean {
		const metadata = this.keyMetadata.get(sessionId)
		if (!metadata) return true
		
		return metadata.failureCount < MAX_RETRY_ATTEMPTS && 
			   Date.now() >= metadata.nextRetry
	}

	async performHealthCheck() {
		if (this.isRefreshing) {
			return
		}

		this.isRefreshing = true
		try {
			const stats = await this.getKeyStoreStats()
			
			if (stats.staleSessions > 0) {
				this.eventEmitter.emit('key.health', {
					staleSessions: stats.staleSessions,
					totalSessions: stats.totalSessions,
					timestamp: Date.now()
				})
				
				console.log(`Key health check: ${stats.staleSessions} stale sessions detected`)
			}
		} catch (error) {
			console.error('Health check error:', error)
		} finally {
			this.isRefreshing = false
		}
	}

	async refreshSession(jid: string, socket?: any): Promise<boolean> {
		// Validate input
		if (!jid || typeof jid !== 'string') {
			console.error(`Invalid JID provided for refresh: ${jid}`)
			return false
		}

		if (this.refreshQueue.has(jid)) {
			console.debug(`Refresh already in progress for ${jid}`)
			return false
		}

		if (this.refreshQueue.size >= this.config.maxConcurrentRefresh) {
			console.warn(`Key refresh queue full (${this.refreshQueue.size}/${this.config.maxConcurrentRefresh}), skipping ${jid}`)
			return false
		}

		this.refreshQueue.add(jid)

		try {
			const sessionId = this.jidToSessionId(jid)
			const healthInfo = await this.checkKeyFreshness(sessionId)
			
			if (healthInfo.isStale) {
				console.log(`Requesting new session for stale key: ${jid} (last activity: ${new Date(healthInfo.lastActivity).toISOString()})`)
				
				// Actually request a new session from WhatsApp servers
				const success = await requestNewSession(jid, this.auth, socket || this.socket)
				
				if (success) {
					// Only update metadata if we actually got a new session
					this.updateKeyMetadata(sessionId, true)
					
					this.eventEmitter.emit('key.refreshed', {
						jid,
						timestamp: Date.now()
					})
					console.log(`Session successfully refreshed for ${jid}`)
					return true
				} else {
					console.warn(`Failed to get new session for ${jid}`)
					this.updateKeyMetadata(sessionId, false)
					return false
				}
			}
			
			console.debug(`Session for ${jid} is not stale, no refresh needed`)
			return false
		} catch (error) {
			console.error(`Failed to refresh session for ${jid}:`, error)
			
			// Safely handle sessionId extraction error
			try {
				const sessionId = this.jidToSessionId(jid)
				this.updateKeyMetadata(sessionId, false)
			} catch (jidError) {
				console.error(`Could not update metadata due to JID error:`, jidError)
			}
			
			return false
		} finally {
			this.refreshQueue.delete(jid)
		}
	}

	async handleDecryptionFailure(jid: string, error: any, socket?: any) {
		if (!error.retryable) {
			return false
		}

		console.log(`Handling decryption failure for ${jid}, attempting session refresh`)
		
		const refreshed = await this.refreshSession(jid, socket || this.socket)
		
		if (refreshed) {
			this.eventEmitter.emit('key.recovery', {
				jid,
				reason: 'decryption_failure',
				timestamp: Date.now()
			})
		}

		return refreshed
	}

	async getSessionHealth(jid: string): Promise<SessionHealthInfo> {
		if (!jid || typeof jid !== 'string') {
			throw new Error(`Invalid JID provided for health check: ${jid}`)
		}
		
		const sessionId = this.jidToSessionId(jid)
		return await this.checkKeyFreshness(sessionId)
	}

	async getKeyStoreStats(): Promise<KeyStoreStats> {
		const sessions = await this.auth.keys.get('session', [])
		const preKeys = await this.auth.keys.get('pre-key', [])
		const senderKeys = await this.auth.keys.get('sender-key', [])
		
		let staleSessions = 0
		const now = Date.now()
		
		for (const [sessionId] of Object.entries(sessions || {})) {
			const metadata = this.keyMetadata.get(sessionId)
			if (metadata && (now - metadata.lastSync > this.config.staleKeyThreshold)) {
				staleSessions++
			}
		}
		
		return {
			totalSessions: Object.keys(sessions || {}).length,
			totalPreKeys: Object.keys(preKeys || {}).length,
			totalSenderKeys: Object.keys(senderKeys || {}).length,
			staleSessions,
			keyMetadataEntries: this.keyMetadata.size
		}
	}

	onDecryptionSuccess(jid: string) {
		if (!jid || typeof jid !== 'string') {
			console.warn(`Invalid JID provided for decryption success: ${jid}`)
			return
		}
		
		try {
			const sessionId = this.jidToSessionId(jid)
			this.updateKeyMetadata(sessionId, true)
		} catch (error) {
			console.error(`Failed to update success metadata for ${jid}:`, error)
		}
	}

	onDecryptionFailure(jid: string) {
		if (!jid || typeof jid !== 'string') {
			console.warn(`Invalid JID provided for decryption failure: ${jid}`)
			return
		}
		
		try {
			const sessionId = this.jidToSessionId(jid)
			this.updateKeyMetadata(sessionId, false)
		} catch (error) {
			console.error(`Failed to update failure metadata for ${jid}:`, error)
		}
	}

	shouldRetryDecryption(jid: string): boolean {
		if (!jid || typeof jid !== 'string') {
			console.warn(`Invalid JID provided for retry check: ${jid}`)
			return false
		}
		
		try {
			const sessionId = this.jidToSessionId(jid)
			return this.shouldRetry(sessionId)
		} catch (error) {
			console.error(`Failed to check retry status for ${jid}:`, error)
			return false
		}
	}

	getStats() {
		return {
			refreshQueueSize: this.refreshQueue.size,
			isRefreshing: this.isRefreshing,
			config: this.config
		}
	}
}

// Helper function to create and initialize key sync manager
export function createKeySyncManager(
	auth: SignalAuthState,
	eventEmitter: BaileysEventEmitter,
	socket?: any,
	config?: Partial<KeySyncConfig>
): KeySyncManager {
	return new KeySyncManager(auth, eventEmitter, socket, config)
}