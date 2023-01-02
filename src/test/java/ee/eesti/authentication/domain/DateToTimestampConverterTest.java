package ee.eesti.authentication.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ee.eesti.AbstractSpringBasedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Date;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

class DateToTimestampConverterTest extends AbstractSpringBasedTest {

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testConvertionOfDateToTimestamp() throws Exception {
        UserInfo userInfo = new UserInfo("1123123123", "1123123123", "1", "John", "Doe", new Date(0L), new Date(42L), "");
        String serializedJson = objectMapper.writeValueAsString(userInfo);

        JsonNode jsonNode = objectMapper.readTree(serializedJson);
        assertThat(jsonNode, is(notNullValue()));
        assertThat(jsonNode.get("loggedInDate").asLong(), is(0L));
        assertThat(jsonNode.get("loginExpireDate").asLong(), is(42L));
    }
}
