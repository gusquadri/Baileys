const { makeWASocket, useMultiFileAuthState, DisconnectReason } = require('@whiskeysockets/baileys')
const { createKeySyncManager } = require('./lib/Utils/key-sync-manager')

async function connectWithKeySync() {
    const { state, saveCreds } = await useMultiFileAuthState('auth_info_baileys')
    
    const sock = makeWASocket({
        auth: state,
        printQRInTerminal: true,
        // Enable enhanced key synchronization
        syncFullHistory: true,
    })
    

    // Create key sync manager for proactive key management
    const keySyncManager = createKeySyncManager(
        state,
        sock.ev,
        sock,
        {
            healthCheckInterval: 10 * 60 * 1000, // Check every 10 minutes
            staleKeyThreshold: 12 * 60 * 60 * 1000, // Consider keys stale after 12 hours
            maxConcurrentRefresh: 5,
            enableProactiveSync: true
        }
    )
    
    sock.ev.on('creds.update', saveCreds)
    
    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update
        if(connection === 'close') {
            const shouldReconnect = (lastDisconnect?.error)?.output?.statusCode !== DisconnectReason.loggedOut
            console.log('connection closed due to ', lastDisconnect?.error, ', reconnecting ', shouldReconnect)
            
            // Stop key sync manager on disconnect
            keySyncManager.stop()
            
            if(shouldReconnect) {
                connectWithKeySync()
            }
        } else if(connection === 'open') {
            console.log('opened connection')
            
            // Start key sync manager when connected
            keySyncManager.start()
            
            // Log initial key store stats
            keySyncManager.getKeyStoreStats().then(stats => {
                console.log('Initial key store stats:', stats)
            })
        }
    })
    
    // Handle key management events
    sock.ev.on('key.health', (data) => {
        console.log(`Key health alert: ${data.staleSessions}/${data.totalSessions} sessions are stale`)
    })
    
    sock.ev.on('key.refreshed', (data) => {
        console.log(`Session refreshed for ${data.jid}`)
    })
    
    sock.ev.on('key.recovery', (data) => {
        console.log(`Key recovery performed for ${data.jid}, reason: ${data.reason}`)
    })
    
    // Handle messages with enhanced error recovery
    sock.ev.on('messages.upsert', async (m) => {
        for (const msg of m.messages) {
            if (msg.message?.encReactionMessage || msg.message?.reactionMessage) {
                // Skip reaction messages
                continue
            }
            
            // Check if this is a decryption failure
            if (msg.messageStubType === 'CIPHERTEXT') {
                console.log(`Decryption failed for message from ${msg.key.remoteJid}`)
                
                // Attempt session refresh
                if (msg.key.remoteJid) {
                    const refreshed = await keySyncManager.refreshSession(msg.key.remoteJid)
                    if (refreshed) {
                        console.log(`Session refreshed, you may want to request message resend`)
                    }
                }
            }
        }
    })
    
    // Periodic key health monitoring
    setInterval(async () => {
        try {
            const stats = await keySyncManager.getKeyStoreStats()
            const syncStats = keySyncManager.getStats()
            
            console.log('Key Store Health Report:', {
                ...stats,
                keySyncManager: syncStats
            })
            
            // Alert if too many stale sessions
            if (stats.staleSessions > stats.totalSessions * 0.1) {
                console.warn(`High number of stale sessions detected: ${stats.staleSessions}/${stats.totalSessions}`)
            }
        } catch (error) {
            console.error('Failed to get key store stats:', error)
        }
    }, 30 * 60 * 1000) // Every 30 minutes
    
    // Manual session health check function
    sock.checkSessionHealth = async (jid) => {
        try {
            const health = await keySyncManager.getSessionHealth(jid)
            console.log(`Session health for ${jid}:`, health)
            return health
        } catch (error) {
            console.error(`Failed to check session health for ${jid}:`, error)
            return null
        }
    }
    
    // Manual session refresh function
    sock.refreshSession = async (jid) => {
        try {
            const refreshed = await keySyncManager.refreshSession(jid)
            console.log(`Session refresh for ${jid}: ${refreshed ? 'success' : 'no action needed'}`)
            return refreshed
        } catch (error) {
            console.error(`Failed to refresh session for ${jid}:`, error)
            return false
        }
    }
    
    // Smart message sending with key management
    sock.sendMessageSmart = async (jid, message, options = {}) => {
        try {
            // Optional: Check if keys are stale before sending (only for important messages)
            if (options.checkKeyHealth) {
                const health = await keySyncManager.getSessionHealth(jid)
                if (health.isStale) {
                    console.log(`Refreshing stale session for ${jid} before sending message`)
                    await keySyncManager.refreshSession(jid)
                }
            }
            
            // Send the message
            const result = await sock.sendMessage(jid, message, options)
            
            // Track successful encryption
            keySyncManager.onDecryptionSuccess(jid)
            
            return result
        } catch (error) {
            // Track failed encryption
            keySyncManager.onDecryptionFailure(jid)
            
            // If it's a key-related error and we should retry
            if ((error.message.includes('key') || error.message.includes('session')) && 
                keySyncManager.shouldRetryDecryption(jid)) {
                
                console.log(`Encryption failed for ${jid}, attempting session refresh and retry`)
                
                const refreshed = await keySyncManager.refreshSession(jid)
                if (refreshed) {
                    // Retry once after refresh
                    return await sock.sendMessage(jid, message, options)
                }
            }
            
            throw error
        }
    }
    
    return sock
}

// Usage example
connectWithKeySync().catch(console.error)

// Export for use in other modules
module.exports = { connectWithKeySync }