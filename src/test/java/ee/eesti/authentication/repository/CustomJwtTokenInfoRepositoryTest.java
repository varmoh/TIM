package ee.eesti.authentication.repository;

import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.repository.entity.CustomJwtTokenInfo;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;


class CustomJwtTokenInfoRepositoryTest extends AbstractSpringBasedTest {

    @Autowired
    private CustomJwtTokenInfoRepository customJwtTokenInfoRepository;

    @Test
    void testSavingOfCustomJwt() {


        CustomJwtTokenInfo customJwt = new CustomJwtTokenInfo();

        customJwt.setExpiredDate(Timestamp.from(Instant.now()));
        customJwt.setJwtUuid(UUID.randomUUID());
        customJwt.setBlacklisted(false);
        customJwt.setIssuedDate(Timestamp.from(Instant.now()));

        CustomJwtTokenInfo saved = customJwtTokenInfoRepository.save(customJwt);

        assertNotNull(saved.getJwtUuid());

    }
}
