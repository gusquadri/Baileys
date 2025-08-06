import { LRUCache } from 'lru-cache'
import type { SignalKeyStoreWithTransaction } from '../Types'
import { DEFAULT_CACHE_TTLS } from '../Defaults'
import { 
    jidNormalizedUser, 
    isLidUser, 
    isJidUser,
    jidDecode
} from '../WABinary'
import type { PrivacyTokenManager } from '../Signal/privacy-tokens'

/**
 * LID-PN mapping storage and management
 * Based on whatsmeow's CachedLIDMap implementation
 * Enhanced with memory-safe caching using lru-cache
 */
export class LIDMappingStore {
    private readonly keys: SignalKeyStoreWithTransaction
    
    // Unified LRU cache for both directions with auto-fetch
    private readonly cache: LRUCache<string, string>
    
    // Privacy token manager for cross-referencing (optional - set via setPrivacyTokenManager)
    private privacyTokenManager?: PrivacyTokenManager
    
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
                        // Convert JID to Redis session key format (preserving device IDs)
                        let sessionKey: string
                        if (key.startsWith('lid-')) {
                            // LID lookup: "lid-102765716062358:43@lid" → "102765716062358_1.43" 
                            const lidJid = key.replace('lid-', '')
                            const decoded = jidDecode(lidJid)
                            if (!decoded) return undefined
                            sessionKey = decoded.device 
                                ? `${decoded.user}_1.${decoded.device}`
                                : `${decoded.user}_1`
                        } else {
                            // PN lookup: "554391318447:43@s.whatsapp.net" → "554391318447.43"
                            const decoded = jidDecode(key)
                            if (!decoded) return undefined
                            sessionKey = decoded.device 
                                ? `${decoded.user}.${decoded.device}`
                                : decoded.user
                        }
                        
                        console.log(`🔍 fetchMethod: cache key="${key}" → Redis key="${sessionKey}"`)
                        
                        const { [sessionKey]: value } = await this.keys.get('lid-mapping', [sessionKey])
                        
                        console.log(`📦 Redis fetch result: ${value || 'NOT FOUND'}`)
                        
                        // If found, convert back to JID format for cache  
                        if (value && typeof value === 'string') {
                            let fullValue: string
                            if (key.startsWith('lid-')) {
                                // LID->PN: "554391318447.43" → "554391318447:43@s.whatsapp.net"
                                const parts = value.split('.')
                                fullValue = parts.length > 1 
                                    ? `${parts[0]}:${parts[1]}@s.whatsapp.net`
                                    : `${parts[0]}@s.whatsapp.net`
                            } else {
                                // PN->LID: "102765716062358_1.43" → "102765716062358:43@lid"
                                const parts = value.replace('_1', '').split('.')
                                fullValue = parts.length > 1
                                    ? `${parts[0]}:${parts[1]}@lid`
                                    : `${parts[0]}@lid`
                            }
                            
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
     * Set privacy token manager for cross-referencing tokens during mapping operations
     * Called after both managers are initialized to avoid circular dependencies
     */
    setPrivacyTokenManager(manager: PrivacyTokenManager): void {
        this.privacyTokenManager = manager
        console.log('🔗 Privacy token manager linked to LID mapping store')
    }

    /**
     * Store a LID-PN mapping (bidirectional) with automatic type detection
     * @param first Either LID or PN JID (e.g., "248274980196484@lid" or "554391318447@s.whatsapp.net")
     * @param second Either PN or LID JID (e.g., "554391318447@s.whatsapp.net" or "248274980196484@lid")
     */
    async storeLIDPNMapping(first: string, second: string): Promise<void> {
        // Smart server type detection like whatsmeow's StoreLIDPNMapping
        let lid: string, pn: string
        
        if (isLidUser(first) && isJidUser(second)) {
            lid = first
            pn = second
        } else if (isJidUser(first) && isLidUser(second)) {
            lid = second
            pn = first
        } else {
            console.log(`⚠️ Invalid LID-PN mapping parameters: first=${first} (isLID=${isLidUser(first)}, isPN=${isJidUser(first)}), second=${second} (isLID=${isLidUser(second)}, isPN=${isJidUser(second)})`)
            return
        }

        // PRESERVE DEVICE IDs: Don't use jidNormalizedUser - it removes device info
        // We need device-specific mappings since each device has separate sessions
        const decoded = jidDecode(pn)
        const lidDecoded = jidDecode(lid)
        
        if (!decoded || !lidDecoded) {
            throw new Error(`Invalid JID format: PN=${pn}, LID=${lid}`)
        }

        // Convert to session-style format with device preservation
        // PN: "554391318447:43@s.whatsapp.net" → "554391318447.43"
        // LID: "102765716062358:43@lid" → "102765716062358_1.43"
        const pnKey = decoded.device 
            ? `${decoded.user}.${decoded.device}`
            : decoded.user
        const lidKey = lidDecoded.device
            ? `${lidDecoded.user}_1.${lidDecoded.device}`  
            : `${lidDecoded.user}_1`

        // Use transaction to ensure atomicity (like other Signal operations)
        try {
            console.log(`📝 Storing LID-PN mapping:`)
            console.log(`  PN: ${pn} → Redis key: ${pnKey}`)
            console.log(`  LID: ${lid} → Redis key: ${lidKey}`)
            
            await this.keys.transaction(async () => {
                // CRITICAL: Invalidate any existing cache entries first
                // This prevents conflicts when relationships change or when sessions are updated
                this.invalidateMapping(lid, pn)
                
                // Store bidirectional mapping using session-style keys
                await this.keys.set({
                    'lid-mapping': {
                        [pnKey]: lidKey,        // "554391318447.63" → "102765716062358_1.63"
                        [lidKey]: pnKey         // "102765716062358_1.63" → "554391318447.63"
                    }
                })
                
                console.log(`✅ Stored in Redis: ${pnKey} ↔ ${lidKey}`)
                
                // Update cache atomically after successful storage (preserve device info)
                this.cache.set(pn, lid)  // Store full JIDs with device IDs
                this.cache.set(`lid-${lid}`, pn)
                
                console.log(`✅ Updated cache: ${pn} ↔ ${lid}`)
                
                // Cross-reference privacy tokens if manager is available (following whatsmeow's approach)
                if (this.privacyTokenManager) {
                    try {
                        // Check if either contact has a privacy token and cross-reference
                        const pnToken = await this.privacyTokenManager.getPrivacyToken(pn)
                        const lidToken = await this.privacyTokenManager.getPrivacyToken(lid)
                        
                        // Cross-reference tokens for both addresses (whatsmeow pattern)
                        if (pnToken && !lidToken) {
                            await this.privacyTokenManager.storePrivacyToken(lid, pnToken.token)
                            console.log(`🔗 Cross-referenced privacy token: ${pn} → ${lid}`)
                        } else if (lidToken && !pnToken) {
                            await this.privacyTokenManager.storePrivacyToken(pn, lidToken.token)
                            console.log(`🔗 Cross-referenced privacy token: ${lid} → ${pn}`)
                        }
                    } catch (tokenError) {
                        console.error('⚠️ Privacy token cross-reference failed (non-critical):', tokenError)
                        // Don't fail the mapping operation for token issues
                    }
                }
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
        
        // DON'T normalize - preserve device ID for device-specific session mapping
        console.log(`🔍 Looking up LID for PN: ${pn} → ${pn}`)
        
        // Use transaction for consistent reads during concurrent writes
        return await this.keys.transaction(async () => {
            // Check cache first (without fetch to see what's actually cached)
            const cachedResult = this.cache.get(pn)
            console.log(`💾 Cache check for "${pn}": ${cachedResult || 'NOT IN CACHE'}`)
            
            // LRU cache handles everything - fetch from storage if needed
            const lid = await this.cache.fetch(pn)
            // fetchMethod already returns properly formatted JID, no need to encode again
            const result = lid || null
            
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
        
        // DON'T normalize - preserve device ID for device-specific session mapping
        
        // Use transaction for consistent reads during concurrent writes
        return await this.keys.transaction(async () => {
            // LRU cache handles everything - fetch from storage if needed
            const pn = await this.cache.fetch(`lid-${lid}`)  // Use full LID with device
            // fetchMethod already returns properly formatted JID, no need to encode again
            return pn || null
        })
    }

    /**
     * Fast cache-only lookup (no Redis fetch) - for performance optimization
     * @param pn Phone number JID
     * @returns Cached LID or null if not in cache
     */
    getFromCache(pn: string): string | null {
        if (!isJidUser(pn)) {
            return null
        }
        
        const cachedLid = this.cache.get(pn)  // Use full JID with device
        
        if (cachedLid) {
            console.log(`⚡ Fast cache hit: ${pn} → ${cachedLid}`)
            return cachedLid  // Already in proper JID format
        }
        
        return null
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
     * Invalidate cache for a specific contact (when session updates)
     */
    invalidateContact(jid: string) {
        if (!isJidUser(jid) && !isLidUser(jid)) return
        
        // Don't normalize - preserve device IDs for cache invalidation
        const cachedValue = this.cache.get(jid)
        
        // Remove both directions from cache
        this.cache.delete(jid)
        if (cachedValue) {
            if (isJidUser(jid)) {
                // PN->LID mapping, remove reverse LID->PN
                this.cache.delete(`lid-${cachedValue}`)
            } else {
                // LID->PN mapping, remove reverse PN->LID  
                this.cache.delete(cachedValue)
            }
        }
        
        console.log(`🗑️ Invalidated cache for: ${jid}`)
    }
    
    /**
     * Invalidate cache for both LID and PN when both are known (more efficient)
     */
    invalidateMapping(lid: string, pn: string) {
        if (!isLidUser(lid) || !isJidUser(pn)) return
        
        // Don't normalize - preserve device IDs for cache invalidation
        
        // Remove both directions from cache
        this.cache.delete(pn)
        this.cache.delete(`lid-${lid}`)
        
        console.log(`🗑️ Invalidated bidirectional cache: ${pn} ↔ ${lid}`)
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