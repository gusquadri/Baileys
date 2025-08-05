import { LRUCache } from 'lru-cache'
import type { SignalKeyStoreWithTransaction } from '../Types'
import { DEFAULT_CACHE_TTLS } from '../Defaults'
import { 
    jidDecode, 
    jidNormalizedUser, 
    isLidUser, 
    isJidUser,
    jidEncode
} from '../WABinary'

/**
 * LID-PN mapping storage and management
 * Based on whatsmeow's CachedLIDMap implementation
 * Enhanced with memory-safe caching using lru-cache
 */
export class LIDMappingStore {
    private readonly keys: SignalKeyStoreWithTransaction
    
    // Unified LRU cache for both directions with auto-fetch
    private readonly cache: LRUCache<string, string>
    
    constructor(keys: SignalKeyStoreWithTransaction) {
        this.keys = keys
        
        // Initialize LRU cache with production-ready settings
        this.cache = new LRUCache<string, string>({
            // Capacity controls
            max: 10000,                                          // Maximum entries
            ttl: (DEFAULT_CACHE_TTLS.LID_STORE || 24 * 60 * 60) * 1000, // 24 hours in ms
            
            // Memory management
            maxSize: 2 * 1024 * 1024,                           // 2MB max memory
            sizeCalculation: (value, key) => {
                return key.length + value.length + 100           // +100 for object overhead
            },
            
            // Performance optimizations
            updateAgeOnGet: true,                                // Keep active entries fresh
            updateAgeOnHas: false,                               // Don't refresh on .has()
            allowStale: false,                                   // Always return fresh data
            
            // Auto-fetch from persistent storage when cache misses
            fetchMethod: async (key: string): Promise<string | undefined> => {
                try {
                    const { [key]: value } = await this.keys.get('lid-mapping', [key])
                    
                    // If found, also cache the reverse mapping
                    if (value && typeof value === 'string') {
                        // Determine if this is a PN->LID or LID->PN lookup
                        if (key.startsWith('lid-')) {
                            // This was a LID->PN lookup, cache PN->LID too
                            const pn = value
                            const lid = key.replace('lid-', '')
                            this.cache.set(pn, lid, { noDisposeOnSet: true })
                        } else {
                            // This was a PN->LID lookup, cache LID->PN too
                            const lid = value
                            const pn = key
                            this.cache.set(`lid-${lid}`, pn, { noDisposeOnSet: true })
                        }
                        
                        return value
                    }
                    
                    return undefined
                } catch (error) {
                    console.error(`Failed to fetch LID mapping for ${key}:`, error)
                    return undefined
                }
            },
            
            // Monitoring and debugging
            dispose: (value, key, reason) => {
                if (reason === 'evict' || reason === 'set') {
                    console.debug(`LID mapping evicted: ${key} (reason: ${reason})`)
                }
            },
            
            // Automatic cleanup
            ttlAutopurge: true,
        })
    }

    /**
     * Store a LID-PN mapping (bidirectional)
     * @param lid LID JID (e.g., "248274980196484@lid")
     * @param pn Phone number JID (e.g., "554391318447@s.whatsapp.net")
     */
    async storeLIDPNMapping(lid: string, pn: string): Promise<void> {
        // Validate inputs using Baileys utilities
        if (!isLidUser(lid) || !isJidUser(pn)) {
            return
        }

        const lidNormalized = jidNormalizedUser(lid)
        const pnNormalized = jidNormalizedUser(pn)

        // Store in persistent storage
        try {
            await this.keys.set({
                'lid-mapping': {
                    [pnNormalized]: lidNormalized,
                    [`lid-${lidNormalized}`]: pnNormalized
                }
            })
            
            // Update cache (both directions)
            // The cache will auto-expire based on TTL
            this.cache.set(pnNormalized, lidNormalized)
            this.cache.set(`lid-${lidNormalized}`, pnNormalized)
        } catch (error) {
            console.error('Failed to store LID-PN mapping:', error)
        }
    }

    /**
     * Get LID for a phone number
     * @param pn Phone number JID (e.g., "554391318447@s.whatsapp.net")
     * @returns LID JID or null if not found
     */
    async getLIDForPN(pn: string): Promise<string | null> {
        if (!isJidUser(pn)) {
            return null
        }
        
        const pnNormalized = jidNormalizedUser(pn)
        
        // LRU cache handles everything - fetch from storage if needed
        const lid = await this.cache.fetch(pnNormalized)
        return lid ? jidEncode(lid, 'lid') : null
    }

    /**
     * Get phone number for a LID
     * @param lid LID JID (e.g., "248274980196484@lid")
     * @returns Phone number JID or null if not found
     */
    async getPNForLID(lid: string): Promise<string | null> {
        if (!isLidUser(lid)) {
            return null
        }
        
        const lidNormalized = jidNormalizedUser(lid)
        
        // LRU cache handles everything - fetch from storage if needed
        const pn = await this.cache.fetch(`lid-${lidNormalized}`)
        return pn ? jidEncode(pn, 's.whatsapp.net') : null
    }

    /**
     * Check if a JID is a LID (reuses Baileys utility)
     */
    static isLID(jid: string): boolean {
        return !!isLidUser(jid)
    }

    /**
     * Check if a JID is a phone number (reuses Baileys utility)
     */
    static isPN(jid: string): boolean {
        return !!isJidUser(jid)
    }
    
    /**
     * Get cache statistics for monitoring
     */
    getStats() {
        return {
            size: this.cache.size,
            calculatedSize: this.cache.calculatedSize,
            maxSize: this.cache.max,
            maxMemory: this.cache.maxSize,
            ttl: this.cache.ttl,
            allowStale: this.cache.allowStale,
            updateAgeOnGet: this.cache.updateAgeOnGet,
        }
    }
    
    /**
     * Clear the cache (useful for testing or manual cleanup)
     */
    clear() {
        this.cache.clear()
    }
    
    /**
     * Pre-warm cache with frequently used mappings
     * Can be called on startup for better performance
     */
    async warmCache(mappings: Array<{ lid: string, pn: string }>) {
        for (const { lid, pn } of mappings) {
            if (isLidUser(lid) && isJidUser(pn)) {
                const lidNormalized = jidNormalizedUser(lid)
                const pnNormalized = jidNormalizedUser(pn)
                
                // Pre-populate cache without triggering fetches
                this.cache.set(pnNormalized, lidNormalized)
                this.cache.set(`lid-${lidNormalized}`, pnNormalized)
            }
        }
    }
}