package core

import model.OtpModel
import model.UserModel
import model.UserStatus
import com.mongodb.client.MongoClient
import io.quarkus.test.junit.QuarkusTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import jakarta.ws.rs.ForbiddenException
import org.junit.jupiter.api.Assertions.assertEquals
import jakarta.inject.Inject
import core.GenericOtpService
import org.bson.types.ObjectId


@QuarkusTest
class GenericOtpServiceTest {

    @Inject lateinit var client: MongoClient

    @Test
    fun `createOrRefresh actually creates a new otp`() {
        val service = GenericOtpService(client, "test-otps")
        val targetUserId: ObjectId = ObjectId()
        service.createOrRefresh(targetUserId)
        val stored = service.findOrPanic(targetUserId)
        assertEquals(targetUserId, stored.userId)
        assertEquals(1, stored.iteration)
    }

    @Test
    fun `createOrRefresh actually refreshes an existing otp`() {
        val service = GenericOtpService(client, "test-otps")
        val targetUserId: ObjectId = ObjectId()
        service.createOrRefresh(targetUserId)
        service.createOrRefresh(targetUserId)
        val stored = service.findOrPanic(targetUserId)
        assertEquals(targetUserId, stored.userId)
        assertEquals(2, stored.iteration)
    }

    @Test
    fun `verifyOtp succeeds with valid otp`() {
        val service = GenericOtpService(client, "test-otps")
        val targetUserId: ObjectId = ObjectId()
        val stored = service.createOrRefresh(targetUserId)
        service.verifyOtp(stored.otp, stored)
    }

    @Test
    fun `verifyOtp fails with invalid otp`() {
        val service = GenericOtpService(client, "test-otps")
        val targetUserId: ObjectId = ObjectId()
        val stored = service.createOrRefresh(targetUserId)
        assertThrows<ForbiddenException> {
            service.verifyOtp("invalid", stored)
        }
        val updated = service.findOrPanic(targetUserId)
        assertEquals(1, updated.attempts)
    }

    @Test
    fun `verifyOtp is not replayable after success`() {
        val service = GenericOtpService(client, "test-otps")
        val targetUserId: ObjectId = ObjectId()
        val stored = service.createOrRefresh(targetUserId)
        service.verifyOtp(stored.otp, stored)
        assertThrows<ForbiddenException> {
            service.verifyOtp(stored.otp, stored)
        }
    }

    @Test
    fun `verifyOtp fails on saturated attempts`() {
        val service = GenericOtpService(client, "test-otps")
        val targetUserId: ObjectId = ObjectId()
        val correctOtp = service.createOrRefresh(targetUserId).otp
        for (attempt in 1..5) {
            assertThrows<ForbiddenException> {
                val freshModel = service.findOrPanic(targetUserId)
                service.verifyOtp("invalid", freshModel)
            }
        }
        assertThrows<ForbiddenException> {
            val freshModel = service.findOrPanic(targetUserId)
            service.verifyOtp(correctOtp, freshModel)
        }
    }

    @Test
    fun `deleteByUserId removes the otp document`() {
        val service = GenericOtpService(client, "test-otps")
        val targetUserId: ObjectId = ObjectId()
        service.createOrRefresh(targetUserId)
        service.deleteByUserId(targetUserId)
        assertThrows<jakarta.ws.rs.NotFoundException> {
            service.findOrPanic(targetUserId)
        }
    }
}
