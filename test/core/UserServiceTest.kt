package core

import model.PasswordModel
import model.UserModel
import model.UserStatus
import io.quarkus.test.junit.QuarkusTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import jakarta.ws.rs.ForbiddenException
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.TestInfo
import jakarta.inject.Inject
import core.UserService
import org.bson.types.ObjectId
import jakarta.ws.rs.ClientErrorException
import jakarta.ws.rs.NotFoundException

@QuarkusTest
class UserServiceTest {

    @Inject lateinit var service: UserService

    @ConfigProperty(name = "primary.tenant")
    lateinit var primaryTenant: String

    fun craftUserModel(tinfo: TestInfo) = UserModel(
        username=tinfo.testMethod.get().name,
        email="${tinfo.testMethod.get().name}@test.example",
        tenant=primaryTenant,
        status=UserStatus.ACTIVE
    )

    @Test
    fun `createOrPanic actually creates a new user`(tinfo: TestInfo) {
        val user = craftUserModel(tinfo)
        val created = service.createOrPanic(user)
        val found = service.findOrPanic(created.email)
        assertEquals(found, created)
    }

    @Test
    fun `createOrPanic actually panics if needed`(tinfo: TestInfo) {
        val user = craftUserModel(tinfo)
        service.createOrPanic(user)
        assertThrows<ClientErrorException> {
            service.createOrPanic(user)
        }
    }

    @Test
    fun `findOrPanic actually panics if needed`(tinfo: TestInfo) {
        val user = craftUserModel(tinfo)
        assertThrows<NotFoundException> {
            service.findOrPanic(user.email)
        }
    }

    @Test
    fun `findOrCreate works fine`(tinfo: TestInfo) {
        val user = craftUserModel(tinfo)
        assertThrows<NotFoundException> {
            service.findOrPanic(user.email)
        }
        val created = service.findOrCreate(user)
        val updated = service.findOrCreate(created)
        val found = service.findOrPanic(created.email)
        assertEquals(found, created)
        assertEquals(found, updated)
    }

    @Test
    fun `findOrCreate panics on conflicts`(tinfo: TestInfo) {
        val user = craftUserModel(tinfo)
        val altered = user.copy(email="different")
        service.findOrCreate(user)
        assertThrows<ClientErrorException> {
            service.findOrCreate(altered)
        }
    }

    @Test
    fun `markAsVerified returns user with ACTIVE status`(tinfo: TestInfo) {
        val user = craftUserModel(tinfo).copy(status = UserStatus.PENDING)
        val created = service.createOrPanic(user)
        val updated = service.markAsVerified(created)
        assertEquals(UserStatus.ACTIVE, updated.status)
    }
}
