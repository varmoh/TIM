package ee.eesti.authentication.service;

import ee.eesti.authentication.repository.CustomJwtTokenInfoRepository;
import ee.eesti.authentication.repository.JwtTokenInfoRepository;
import ee.eesti.authentication.repository.WhitelistRepository;
import ee.eesti.authentication.repository.entity.CustomJwtTokenInfo;
import ee.eesti.authentication.repository.entity.JwtTokenInfo;
import ee.eesti.authentication.repository.entity.JwtWhitelistEntity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
public class WhiteListService {

    private final WhitelistRepository repository;
    private final CustomJwtTokenInfoRepository customJwts;
    private final JwtTokenInfoRepository jwts;
    private final JwtTokenInfoService jwtService;

    public WhiteListService(WhitelistRepository repository, CustomJwtTokenInfoRepository customJwts, JwtTokenInfoRepository jwts, JwtTokenInfoService jwtService) {
        this.repository = repository;
        this.customJwts = customJwts;
        this.jwts = jwts;
        this.jwtService = jwtService;
    }

    public boolean addSessionToAllowlist(String sessionHash, Timestamp expiredAt) {
        JwtWhitelistEntity entity =
                new JwtWhitelistEntity();
        entity.setJwtHash(sessionHash);
        entity.setExpirationDate(expiredAt);
        entity = repository.saveAndFlush(entity);
        log.debug("{} added to whitelist", entity.getJwtHash());
        return true;
    }

    private void blacklist(String id) {
        UUID uuid = UUID.fromString(id);
        JwtTokenInfo jwt = jwts.getReferenceById(uuid);
        jwtService.blacklist(jwt);
        CustomJwtTokenInfo cjwt = customJwts.getReferenceById(uuid);
        jwtService.blacklist(cjwt);
    }

    @Scheduled(fixedDelayString = "${jwt.whitelist.period}")
    public void scheduleBlacklisting() {
        List<JwtWhitelistEntity> whitelistEntities = repository.findByExpirationDateBefore(LocalDateTime.now());

        whitelistEntities.forEach(
                entity -> {
                    blacklist(entity.getJwtHash());
                    log.debug("Blacklisted {}", entity);
                }
        );

        log.trace("JWT blacklisting update tick");
    }

}
