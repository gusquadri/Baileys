import type { SignalKeyStoreWithTransaction } from '../Types'
import { jidNormalizedUser, isJidUser, isLidUser } from '../WABinary'
import type { LIDMappingStore } from '../Utils/lid-mapping'

/**
 * Privacy token data structure following whatsmeow's approach
 */
export interface PrivacyTokenData {
    token: Buffer
    timestamp: number
}

/**
 * Privacy token utility constants
 */
export const PRIVACY_TOKEN_CONSTANTS = {
    // Token expiration time (24 hours like whatsmeow)
    TOKEN_TTL_MS: 24 * 60 * 60 * 1000,
} as const

/**
 * Privacy Token Manager - handles WhatsApp privacy tokens following whatsmeow patterns
 * 
 * Privacy tokens (tcToken) are cryptographic authorization tokens that control access
 * to user presence and messaging capabilities. They work alongside LID addresses.
 * 
 * Uses external persistent storage (Redis/database) for better memory efficiency
 * and consistency with Baileys external storage architecture.
 */
export class PrivacyTokenManager {
    private readonly keys: SignalKeyStoreWithTransaction
    private readonly lidMapping: LIDMappingStore
    
    constructor(keys: SignalKeyStoreWithTransaction, lidMapping: LIDMappingStore) {
        this.keys = keys
        this.lidMapping = lidMapping
    }

    /**
     * Store a privacy token for a contact (following whatsmeow's StorePrivacyToken)
     * Automatically handles LID-PN cross-referencing
     */
    async storePrivacyToken(jid: string, token: Buffer): Promise<void> {
        const normalizedJid = jidNormalizedUser(jid)
        const timestamp = Date.now()
        const tokenData: PrivacyTokenData = { token, timestamp }
        
        try {
            await this.keys.transaction(async () => {
                // Store primary token in persistent storage
                await this.keys.set({
                    'privacy-tokens': {
                        [normalizedJid]: tokenData
                    }
                })
                
                // Cross-reference with LID mapping (following whatsmeow's approach)
                await this.crossReferenceToken(normalizedJid, token, timestamp)
                
                console.log(`✅ Stored privacy token for ${normalizedJid} (${token.length} bytes)`)
            })
        } catch (error) {
            console.error(`❌ Failed to store privacy token for ${normalizedJid}:`, error)
            throw error
        }
    }

    /**
     * Get a privacy token for a contact (following whatsmeow's GetPrivacyToken)
     * Returns the freshest token available from either PN or LID mapping
     */
    async getPrivacyToken(jid: string): Promise<PrivacyTokenData | null> {
        const normalizedJid = jidNormalizedUser(jid)
        
        try {
            return await this.keys.transaction(async () => {
                // Check direct storage
                const { [normalizedJid]: tokenData } = await this.keys.get('privacy-tokens', [normalizedJid])
                
                if (tokenData && !this.isTokenExpired(tokenData)) {
                    console.log(`📦 Privacy token found for ${normalizedJid}`)
                    return tokenData
                }
                
                // Try alternative addressing (LID-PN cross-lookup)
                const alternativeToken = await this.findAlternativeToken(normalizedJid)
                if (alternativeToken && !this.isTokenExpired(alternativeToken)) {
                    // Store in primary location for future lookups
                    await this.keys.set({
                        'privacy-tokens': {
                            [normalizedJid]: alternativeToken
                        }
                    })
                    console.log(`🔄 Privacy token found via alternative addressing for ${normalizedJid}`)
                    return alternativeToken
                }
                
                console.log(`❌ No privacy token found for ${normalizedJid}`)
                return null
            })
        } catch (error) {
            console.error(`Failed to get privacy token for ${normalizedJid}:`, error)
            return null
        }
    }

    /**
     * Check if a contact requires a privacy token for messaging
     * Following whatsmeow's privacy requirements logic
     */
    async requiresPrivacyToken(jid: string): Promise<boolean> {
        const normalizedJid = jidNormalizedUser(jid)
        
        // LID contacts always require privacy tokens (enhanced privacy)
        if (isLidUser(normalizedJid)) {
            return true
        }
        
        // Check if we have a token (indicates prior enhanced privacy interaction)
        const token = await this.getPrivacyToken(normalizedJid)
        return token !== null
    }

    /**
     * Migrate privacy tokens during LID-PN session migration
     * Critical for maintaining privacy authorization across address changes
     */
    async migratePrivacyToken(fromJid: string, toJid: string): Promise<void> {
        const fromNormalized = jidNormalizedUser(fromJid)
        const toNormalized = jidNormalizedUser(toJid)
        
        if (fromNormalized === toNormalized) {
            return // No migration needed
        }
        
        try {
            await this.keys.transaction(async () => {
                const token = await this.getPrivacyToken(fromNormalized)
                if (token) {
                    await this.keys.set({
                        'privacy-tokens': {
                            [toNormalized]: token
                        }
                    })
                    console.log(`🔄 Migrated privacy token: ${fromNormalized} → ${toNormalized}`)
                }
            })
        } catch (error) {
            console.error(`Failed to migrate privacy token from ${fromJid} to ${toJid}:`, error)
        }
    }

    /**
     * Get basic statistics (simplified without cache)
     */
    getCacheStats() {
        return {
            note: 'Privacy tokens stored in external persistent storage',
            implementation: 'External storage - no in-memory cache'
        }
    }

    /**
     * Clear privacy tokens (primarily for testing)
     */
    async clearAllTokens(): Promise<void> {
        console.log('🧹 Privacy token clearing would require iterating storage keys - not implemented')
        console.log('Use external storage admin tools to clear privacy-tokens if needed')
    }

    // Private helper methods

    /**
     * Cross-reference privacy token with LID mapping
     */
    private async crossReferenceToken(jid: string, token: Buffer, timestamp: number): Promise<void> {
        try {
            if (isLidUser(jid)) {
                // LID → PN cross-reference
                const pn = await this.lidMapping.getPNForLID(jid)
                if (pn) {
                    const pnNormalized = jidNormalizedUser(pn)
                    await this.keys.set({
                        'privacy-tokens': {
                            [pnNormalized]: { token, timestamp }
                        }
                    })
                    console.log(`🔗 Cross-referenced privacy token: ${jid} → ${pnNormalized}`)
                }
            } else if (isJidUser(jid)) {
                // PN → LID cross-reference
                const lid = await this.lidMapping.getLIDForPN(jid)
                if (lid) {
                    const lidNormalized = jidNormalizedUser(lid)
                    await this.keys.set({
                        'privacy-tokens': {
                            [lidNormalized]: { token, timestamp }
                        }
                    })
                    console.log(`🔗 Cross-referenced privacy token: ${jid} → ${lidNormalized}`)
                }
            }
        } catch (error) {
            console.error(`Failed to cross-reference privacy token for ${jid}:`, error)
        }
    }

    /**
     * Find alternative token via LID-PN mapping
     */
    private async findAlternativeToken(jid: string): Promise<PrivacyTokenData | null> {
        try {
            let alternativeJid: string | null = null
            
            if (isLidUser(jid)) {
                alternativeJid = await this.lidMapping.getPNForLID(jid)
            } else if (isJidUser(jid)) {
                alternativeJid = await this.lidMapping.getLIDForPN(jid)
            }
            
            if (alternativeJid) {
                const altNormalized = jidNormalizedUser(alternativeJid)
                const { [altNormalized]: tokenData } = await this.keys.get('privacy-tokens', [altNormalized])
                
                if (tokenData) {
                    return tokenData
                }
            }
            
            return null
        } catch (error) {
            console.error(`Failed to find alternative privacy token for ${jid}:`, error)
            return null
        }
    }

    /**
     * Check if a token is expired
     */
    private isTokenExpired(tokenData: PrivacyTokenData): boolean {
        const now = Date.now()
        return (now - tokenData.timestamp) > PRIVACY_TOKEN_CONSTANTS.TOKEN_TTL_MS
    }
}

/**
 * Utility functions for privacy token handling
 */
export const PrivacyTokenUtils = {
    /**
     * Check if a JID format suggests privacy token requirement
     */
    isPrivacyEnhanced(jid: string): boolean {
        return !!isLidUser(jid)
    },

    /**
     * Create privacy token node for message sending
     */
    createTokenNode(token: Buffer): { tag: string; attrs: {}; content: Buffer } {
        return {
            tag: 'tctoken',
            attrs: {},
            content: token
        }
    },

    /**
     * Validate token buffer format
     */
    isValidToken(token: Buffer): boolean {
        return Buffer.isBuffer(token) && token.length >= 16 && token.length <= 64
    },

    /**
     * Create token storage key
     */
    createTokenKey(jid: string): string {
        return jidNormalizedUser(jid)
    }
}