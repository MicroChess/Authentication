package core

import model.UserModel
import model.UserStatus
import io.quarkus.test.junit.QuarkusTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import jakarta.inject.Inject
import org.bson.types.ObjectId

@QuarkusTest
class TokenServiceTest {

    @Inject lateinit var service: TokenService

    private fun craftUserModel() = UserModel(
        id = ObjectId(),
        username = "tokentest",
        email = "tokentest@example.com",
        tenant = "microchess",
        status = UserStatus.ACTIVE
    )

    @Test
    fun `emitNewToken and parseJsonWebToken round-trip correctly`() {
        val user = craftUserModel()
        val token = service.emitNewToken(user)
        val parsed = service.parseJsonWebToken(token)
        assertEquals(user.username, parsed.username)
        assertEquals(user.email, parsed.email)
        assertEquals(user.status, parsed.status)
        assertEquals(user.tenant, parsed.tenant)
        assertEquals(user.id.toString(), parsed.id.toString())
    }

    @Test
    fun `parseJsonWebToken deserialises status enum correctly`() {
        val user = craftUserModel().copy(status = UserStatus.PENDING)
        val token = service.emitNewToken(user)
        val parsed = service.parseJsonWebToken(token)
        assertEquals(UserStatus.PENDING, parsed.status)
    }

    @Test
    fun `emitAuthorizedResponse includes Authorization Bearer header`() {
        val user = craftUserModel()
        val response = service.emitAuthorizedResponse(user)
        val authHeader = response.headers["Authorization"]?.firstOrNull()?.toString()
        assertNotNull(authHeader)
        assertTrue(authHeader!!.startsWith("Bearer "))
    }

    @Test
    fun `token signed by class-level key is verifiable`() {
        val user = craftUserModel()
        val token = service.emitNewToken(user)
        val parsed = service.parseJsonWebToken(token)
        assertEquals(user.username, parsed.username)
    }
}
