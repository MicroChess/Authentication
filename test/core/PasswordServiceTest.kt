package core

import model.PasswordModel
import model.UserModel
import model.UserStatus
import io.quarkus.test.junit.QuarkusTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import jakarta.ws.rs.ForbiddenException
import jakarta.ws.rs.NotFoundException
import org.junit.jupiter.api.Assertions.assertEquals
import jakarta.inject.Inject
import core.PasswordService
import org.bson.types.ObjectId

@QuarkusTest
class PasswordServiceTest {

    @Inject lateinit var service: PasswordService

    @Test
    fun `createOrUpdate actually creates a new password`() {
        val targetUserId = ObjectId()
        service.createOrUpdate("newPassword", targetUserId)
        val stored = service.findOrPanic(targetUserId)
        service.verifyPassword("newPassword", stored)
    }

    @Test
    fun `createOrUpdate actually updates the hash in the database`() {
        val targetUserId = ObjectId()
        service.createOrUpdate("oldPassword", targetUserId)
        service.createOrUpdate("newPassword", targetUserId)
        val stored = service.findOrPanic(targetUserId)
        service.verifyPassword("newPassword", stored)
    }

    @Test
    fun `verifyPassword fails with incorrect password`() {
        val targetUserId = ObjectId()
        service.createOrUpdate("newPassword", targetUserId)
        val stored = service.findOrPanic(targetUserId)
        val exception = assertThrows<ForbiddenException> {
            service.verifyPassword("incorrectPassword", stored)
        }
        assertEquals("Invalid Password", exception.message)
    }

    @Test
    fun `deleteByUserId removes the password record`() {
        val targetUserId = ObjectId()
        service.createOrUpdate("somePassword", targetUserId)
        service.deleteByUserId(targetUserId)
        assertThrows<NotFoundException> {
            service.findOrPanic(targetUserId)
        }
    }
}
