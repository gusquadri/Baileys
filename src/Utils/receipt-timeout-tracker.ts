import type { WAMessageKey } from '../Types'
import type { ILogger } from './logger'

/**
 * Receipt Timeout Tracker - WhatsmeOW-inspired delivery reliability
 * Tracks which devices don't send receipts and triggers resends
 */
export class ReceiptTimeoutTracker {
    private readonly logger: ILogger
    private readonly resendCallback: (messageKey: WAMessageKey, targetDevices: string[]) => Promise<void>
    
    // Track pending receipts: messageId -> {devices: Set<deviceJid>, timer: NodeJS.Timeout}
    private readonly pendingReceipts = new Map<string, {
        messageKey: WAMessageKey
        targetDevices: Set<string>
        timer: NodeJS.Timeout
        sentTime: number
    }>()
    
    // Track delivery attempts per device: "messageId:deviceJid" -> attemptCount
    private readonly deliveryAttempts = new Map<string, number>()
    
    // Configuration
    private readonly receiptTimeout = 10000 // 10 seconds like you requested
    private readonly maxRetryAttempts = 3   // Max resends per device
    private readonly cleanupInterval = 5 * 60 * 1000 // 5 minutes cleanup

    constructor(
        logger: ILogger,
        resendCallback: (messageKey: WAMessageKey, targetDevices: string[]) => Promise<void>
    ) {
        this.logger = logger
        this.resendCallback = resendCallback
        
        // Periodic cleanup of old entries
        setInterval(() => this.cleanupOldEntries(), this.cleanupInterval)
    }

    /**
     * Start tracking receipt timeout for a message sent to multiple devices
     */
    startTracking(messageKey: WAMessageKey, targetDevices: string[]): void {
        if (!messageKey.id || !messageKey.remoteJid) {
            this.logger.warn('Invalid message key for receipt tracking')
            return
        }

        const messageId = messageKey.id
        const devicesSet = new Set(targetDevices)
        
        // Don't track if no devices to monitor
        if (devicesSet.size === 0) {
            return
        }

        this.logger.debug({
            messageId,
            remoteJid: messageKey.remoteJid,
            targetDevices,
            timeout: this.receiptTimeout
        }, 'Starting receipt timeout tracking')

        // Clear any existing timer for this message
        this.stopTracking(messageId)

        // Set timeout timer
        const timer = setTimeout(() => {
            this.handleReceiptTimeout(messageId)
        }, this.receiptTimeout)

        this.pendingReceipts.set(messageId, {
            messageKey,
            targetDevices: devicesSet,
            timer,
            sentTime: Date.now()
        })
    }

    /**
     * Mark receipt received from a specific device
     */
    markReceiptReceived(messageId: string, deviceJid: string): void {
        const tracking = this.pendingReceipts.get(messageId)
        if (!tracking) {
            return // Not tracking this message
        }

        this.logger.debug({
            messageId,
            deviceJid,
            remainingDevices: tracking.targetDevices.size - 1
        }, 'Receipt received from device')

        // Remove this device from pending list
        tracking.targetDevices.delete(deviceJid)

        // If all devices acknowledged, stop tracking
        if (tracking.targetDevices.size === 0) {
            this.logger.debug({ messageId }, 'All devices acknowledged - stopping tracking')
            this.stopTracking(messageId)
        }
    }

    /**
     * Handle receipt timeout - resend to devices that didn't acknowledge
     */
    private async handleReceiptTimeout(messageId: string): Promise<void> {
        const tracking = this.pendingReceipts.get(messageId)
        if (!tracking) {
            return
        }

        const missingDevices = Array.from(tracking.targetDevices)
        const elapsedTime = Date.now() - tracking.sentTime

        this.logger.warn({
            messageId,
            remoteJid: tracking.messageKey.remoteJid,
            missingDevices,
            elapsedTime,
            timeout: this.receiptTimeout
        }, 'Receipt timeout - devices did not acknowledge')

        // Filter devices that haven't exceeded retry limit
        const devicesToRetry: string[] = []
        const devicesGivingUp: string[] = []

        for (const deviceJid of missingDevices) {
            const attemptKey = `${messageId}:${deviceJid}`
            const attempts = (this.deliveryAttempts.get(attemptKey) || 0) + 1
            
            this.deliveryAttempts.set(attemptKey, attempts)

            if (attempts <= this.maxRetryAttempts) {
                devicesToRetry.push(deviceJid)
            } else {
                devicesGivingUp.push(deviceJid)
                this.logger.error({
                    messageId,
                    deviceJid,
                    attempts,
                    maxAttempts: this.maxRetryAttempts
                }, 'Giving up on device after max retry attempts')
            }
        }

        // Clean up tracking for this message
        this.stopTracking(messageId)

        // Trigger resend for devices that can still be retried
        if (devicesToRetry.length > 0) {
            this.logger.info({
                messageId,
                devicesToRetry,
                attemptNumber: Math.max(...devicesToRetry.map(d => 
                    this.deliveryAttempts.get(`${messageId}:${d}`) || 1
                ))
            }, 'Triggering message resend to specific devices')

            try {
                await this.resendCallback(tracking.messageKey, devicesToRetry)
                
                // Restart tracking for the retried devices
                this.startTracking(tracking.messageKey, devicesToRetry)
            } catch (error: any) {
                this.logger.error({
                    messageId,
                    devicesToRetry,
                    error: error?.message || 'Unknown error'
                }, 'Failed to resend message to devices')
            }
        }

        // Log final failures
        if (devicesGivingUp.length > 0) {
            this.logger.error({
                messageId,
                remoteJid: tracking.messageKey.remoteJid,
                failedDevices: devicesGivingUp,
                maxAttempts: this.maxRetryAttempts
            }, 'Message delivery permanently failed for devices')
        }
    }

    /**
     * Stop tracking a message (clear timer and remove from pending)
     */
    private stopTracking(messageId: string): void {
        const tracking = this.pendingReceipts.get(messageId)
        if (tracking) {
            clearTimeout(tracking.timer)
            this.pendingReceipts.delete(messageId)
        }
    }

    /**
     * Clean up old delivery attempt records
     */
    private cleanupOldEntries(): void {
        let cleanedAttempts = 0

        // Clean up old delivery attempts (simple cleanup - remove all after 24h)
        // In production, you'd track timestamps per attempt
        if (this.deliveryAttempts.size > 1000) { // Prevent memory leaks
            this.deliveryAttempts.clear()
            cleanedAttempts = this.deliveryAttempts.size
        }

        if (cleanedAttempts > 0) {
            this.logger.debug({ cleanedAttempts }, 'Cleaned up old delivery attempt records')
        }
    }

    /**
     * Get current tracking statistics
     */
    getTrackingStats() {
        return {
            pendingMessages: this.pendingReceipts.size,
            trackedAttempts: this.deliveryAttempts.size,
            timeout: this.receiptTimeout,
            maxRetries: this.maxRetryAttempts
        }
    }

    /**
     * Force stop tracking all messages (for shutdown)
     */
    shutdown(): void {
        for (const [messageId] of this.pendingReceipts) {
            this.stopTracking(messageId)
        }
        this.deliveryAttempts.clear()
        this.logger.info('Receipt timeout tracker shutdown complete')
    }

    /**
     * Check if a message is currently being tracked
     */
    isTracking(messageId: string): boolean {
        return this.pendingReceipts.has(messageId)
    }

    /**
     * Get remaining devices for a tracked message
     */
    getRemainingDevices(messageId: string): string[] {
        const tracking = this.pendingReceipts.get(messageId)
        return tracking ? Array.from(tracking.targetDevices) : []
    }
}