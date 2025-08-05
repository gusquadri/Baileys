import { LRUCache } from 'lru-cache'
import type { SignalKeyStoreWithTransaction } from '../Types'
import { DEFAULT_CACHE_TTLS } from '../Defaults'
import { 
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
                    // Use transaction to prevent race conditions during fetch
                    return await this.keys.transaction(async () => {
                        // Simple direct key lookup - Redis keys match our storage format
                        const sessionKey = key.startsWith('lid-') 
                            ? key.replace('lid-', '').replace('@lid', '').replace(':', '.') + '_1'
                            : key.replace('@s.whatsapp.net', '').replace(':', '.')
                        
                        console.log(`🔍 fetchMethod: cache key="${key}" → Redis key="${sessionKey}"`)
                        
                        const { [sessionKey]: value } = await this.keys.get('lid-mapping', [sessionKey])
                        
                        console.log(`📦 Redis fetch result: ${value || 'NOT FOUND'}`)
                        
                        // If found, convert back to JID format for cache
                        if (value && typeof value === 'string') {
                            const fullValue = key.startsWith('lid-')
                                ? value.replace('.', ':') + '@s.whatsapp.net'  // LID->PN lookup
                                : value.replace('_1', '').replace('.', ':') + '@lid'  // PN->LID lookup
                            
                            console.log(`✅ fetchMethod returning: ${fullValue}`)
                            return fullValue
                        }
                        
                        return undefined
                    })
                } catch (error) {
                    console.error(`Failed to fetch LID mapping for ${key}:`, error)
                    return undefined
                }
            },
            
            // Monitoring and debugging
            dispose: (_value, key, reason) => {
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

        // Convert to session-style format matching your Redis pattern
        // PN: "554391318447@s.whatsapp.net" → "554391318447"
        // LID: "102765716062358@lid" → "102765716062358_1"
        const pnKey = pnNormalized.replace('@s.whatsapp.net', '').replace(':', '.')
        const lidKey = lidNormalized.replace('@lid', '').replace(':', '.') + '_1'

        // Use transaction to ensure atomicity (like other Signal operations)
        try {
            console.log(`📝 Storing LID-PN mapping:`)
            console.log(`  PN: ${pn} → ${pnNormalized} → Redis key: ${pnKey}`)
            console.log(`  LID: ${lid} → ${lidNormalized} → Redis key: ${lidKey}`)
            
            await this.keys.transaction(async () => {
                // Store bidirectional mapping using session-style keys
                await this.keys.set({
                    'lid-mapping': {
                        [pnKey]: lidKey,        // "554391318447.63" → "102765716062358_1.63"
                        [lidKey]: pnKey         // "102765716062358_1.63" → "554391318447.63"
                    }
                })
                
                console.log(`✅ Stored in Redis: ${pnKey} ↔ ${lidKey}`)
                
                // Update cache atomically after successful storage (use original normalized format)
                this.cache.set(pnNormalized, lidNormalized)
                this.cache.set(`lid-${lidNormalized}`, pnNormalized)
                
                console.log(`✅ Updated cache: ${pnNormalized} ↔ ${lidNormalized}`)
            })
        } catch (error) {
            console.error('❌ Failed to store LID-PN mapping:', error)
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
        
        console.log(`🔍 Looking up LID for PN: ${pn} → ${pnNormalized}`)
        
        // Use transaction for consistent reads during concurrent writes
        return await this.keys.transaction(async () => {
            // LRU cache handles everything - fetch from storage if needed
            const lid = await this.cache.fetch(pnNormalized)
            const result = lid ? jidEncode(lid, 'lid') : null
            
            console.log(`${result ? '✅' : '❌'} LID lookup result: ${result || 'NOT FOUND'}`)
            return result
        })
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
        
        // Use transaction for consistent reads during concurrent writes
        return await this.keys.transaction(async () => {
            // LRU cache handles everything - fetch from storage if needed
            const pn = await this.cache.fetch(`lid-${lidNormalized}`)
            return pn ? jidEncode(pn, 's.whatsapp.net') : null
        })
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
     * Debug helper - check if mapping exists in storage
     */
    async debugMapping(identifier: string): Promise<void> {
        console.log(`🔍 Debug mapping for: ${identifier}`)
        
        try {
            // Check cache first
            const cacheKey = identifier.includes('@') ? identifier : `${identifier}@s.whatsapp.net`
            const cacheResult = this.cache.get(cacheKey)
            console.log(`Cache result: ${cacheResult || 'NOT FOUND'}`)
            
            // Check Redis directly 
            const sessionKey = identifier.replace('@s.whatsapp.net', '').replace(':', '.')
            const { [sessionKey]: redisResult } = await this.keys.get('lid-mapping', [sessionKey])
            console.log(`Redis result for key '${sessionKey}': ${redisResult || 'NOT FOUND'}`)
            
            // Try reverse lookup if it's a LID
            if (identifier.includes('_1')) {
                const lidKey = sessionKey
                const { [lidKey]: reverseLookup } = await this.keys.get('lid-mapping', [lidKey])
                console.log(`Reverse Redis result for key '${lidKey}': ${reverseLookup || 'NOT FOUND'}`)
            }
            
        } catch (error) {
            console.error(`Debug mapping failed:`, error)
        }
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