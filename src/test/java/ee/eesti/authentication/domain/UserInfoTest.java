package ee.eesti.authentication.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.*;

class UserInfoTest {


    @Test
    void testStrippedPersonalCode() {
        UserInfo userInfo = new UserInfo();

        userInfo.setPersonalCode("EE12345678901");
        assertThat(userInfo.getPersonalCodeWithoutCountryPrefix(), is("12345678901"));

        userInfo.setPersonalCode("  EE12345678901   ");
        assertThat(userInfo.getPersonalCodeWithoutCountryPrefix(), is("12345678901"));

        userInfo.setPersonalCode("  lV12345678901   ");
        assertThat(userInfo.getPersonalCodeWithoutCountryPrefix(), is("12345678901"));

        userInfo.setPersonalCode("  Ru12345678901   ");
        assertThat(userInfo.getPersonalCodeWithoutCountryPrefix(), is("12345678901"));

        userInfo.setPersonalCode("09876543210");
        assertThat(userInfo.getPersonalCodeWithoutCountryPrefix(), is("09876543210"));

        userInfo.setPersonalCode("someInvalidString");
        assertThat(userInfo.getPersonalCodeWithoutCountryPrefix(), is("someInvalidString"));
    }


    @Test
    void testUserCountryPrefixFromPersonalCode() {

        UserInfo userInfo = new UserInfo();

        userInfo.setPersonalCode("EE12345678901");
        assertThat(userInfo.getCountryPrefix(), is("EE"));

        userInfo.setPersonalCode("LT12345678901");
        assertThat(userInfo.getCountryPrefix(), is("LT"));

        userInfo.setPersonalCode(null);
        assertNull(userInfo.getCountryPrefix());

        // according to https://e-gov.github.io/TARA-Doku/TehnilineKirjeldus#431-identsust%C3%B5end
        // personalCode contains ISO 3166-1 alpha-2 country code
        userInfo.setPersonalCode("11123123123");
        assertNull(userInfo.getCountryPrefix());

    }

    @Test
    void testEstonianPersonalCodePrefix() {
        UserInfo userInfo = new UserInfo();

        userInfo.setPersonalCode("EE12345678901");
        assertTrue(userInfo.isHasEstonianPersonalCode());

        userInfo.setPersonalCode("LT12345678901");
        assertFalse(userInfo.isHasEstonianPersonalCode());

        userInfo.setPersonalCode(null);
        assertFalse(userInfo.isHasEstonianPersonalCode());

    }

    @Test
    void testJsonIgnoreSerialization() throws IOException {
        UserInfo userInfo = new UserInfo();
        ObjectMapper objectMapper = new ObjectMapper();
        String valueAsString = objectMapper.writeValueAsString(userInfo);

        System.out.println(valueAsString);
        JsonNode jsonNode = objectMapper.readTree(valueAsString);

        assertTrue(jsonNode.path("personalCodeWithoutCountryPrefix").isMissingNode());
        assertTrue(jsonNode.path("countryPrefix").isMissingNode());
        assertTrue(jsonNode.path("hasEstonianPersonalCode").isMissingNode());
    }
}
