package mikhail.shell.video.hosting.security

import com.github.benmanes.caffeine.cache.Caffeine
import io.github.bucket4j.Bandwidth
import io.github.bucket4j.Bucket
import io.github.bucket4j.local.LocalBucket
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import mikhail.shell.video.hosting.security.RateLimitFilter.BucketKey.AuthInfo.Ip
import mikhail.shell.video.hosting.security.RateLimitFilter.BucketKey.AuthInfo.UserId
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.time.Duration

@Component
class RateLimitFilter : OncePerRequestFilter() {
    private data class BucketKey(
        val endpointGroup: EndpointGroup,
        val authInfo: AuthInfo
    ) {
        enum class EndpointGroup (
            val requestsPerMinute: Long
        ) {
            AUTHENTICATION(10),
            MODIFICATION(30),
            HEAVY(60),
            DEFAULT(500)
        }
        sealed interface AuthInfo {
            data class Ip (val ip: String): AuthInfo
            data class UserId(val userId: Long): AuthInfo
        }
    }
    private val tokenBuckets = Caffeine.newBuilder()
        .expireAfterAccess(Duration.ofMinutes(30))
        .maximumSize(100_000)
        .build<BucketKey, Bucket>()

    private fun createBucket(endpointGroup: BucketKey.EndpointGroup): LocalBucket {
        return Bucket.builder()
            .addLimit(
                Bandwidth.builder()
                    .capacity(endpointGroup.requestsPerMinute)
                    .refillIntervally(endpointGroup.requestsPerMinute, Duration.ofMinutes(1))
                    .build()
            )
            .build()
    }

    private fun HttpServletRequest.getBucketKey(): BucketKey {
        val endpointGroup = when {
            requestURI.startsWith("/api/v2/auth") -> BucketKey.EndpointGroup.AUTHENTICATION
            sourcePathPattern.matches(this) -> BucketKey.EndpointGroup.HEAVY
            method in listOf("POST", "PUT", "DELETE") -> BucketKey.EndpointGroup.MODIFICATION
            else -> BucketKey.EndpointGroup.DEFAULT
        }

        val authInfo: BucketKey.AuthInfo = run {
            val videoHostingToken = SecurityContextHolder.getContext().authentication as VideoHostingToken?
            if (videoHostingToken != null) {
                return@run UserId(videoHostingToken.principal!! as Long)
            }
            val forwardedForIpHeader = getHeader("X-Forwarded-For")
            if (forwardedForIpHeader != null) {
                if (forwardedForIpHeader.contains(",")) {
                    return@run Ip(forwardedForIpHeader.substringBefore(","))
                }
                return@run Ip(forwardedForIpHeader)
            }
            return@run Ip(remoteAddr)
        }

        return BucketKey(endpointGroup, authInfo)
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val bucket = tokenBuckets.get(request.getBucketKey()) {
            createBucket(it.endpointGroup)
        }
        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response)
        } else {
            response.status = HttpStatus.TOO_MANY_REQUESTS.value()
        }
    }
    private companion object {
        val sourcePathPattern = PathPatternRequestMatcher.pathPattern("/api/v2/videos/{id}/source")
    }
}