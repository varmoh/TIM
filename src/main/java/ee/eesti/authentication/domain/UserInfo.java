package ee.eesti.authentication.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

/**
 * Models the user info.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserInfo {

    private static final String ESTONIAN_PERSONAL_CODE_PREFIX = "EE";

    private String personalCode;
    private String authenticatedAs;
    private String hash;
    private String firstName;
    private String lastName;
    @JsonSerialize(using = DateToTimestampConverter.class)
    private Date loggedInDate;
    @JsonSerialize(using = DateToTimestampConverter.class)
    private Date loginExpireDate;
    private String authMethod;

    public String getFullName() {
        return firstName + " " + lastName;
    }

    @JsonIgnore
    public String getPersonalCodeWithoutCountryPrefix() {
        if (personalCode == null) {
            return null;
        }

        return personalCode.trim().matches("^[a-zA-Z]{2}\\d{11}$")
                ? personalCode.trim().substring(2)
                : personalCode;
    }

    @JsonIgnore
    public String getCountryPrefix(){
        if (personalCode == null) {
            return null;
        }

        String countryPrefix = personalCode.substring(0, 2);

        return countryPrefix.matches("^[a-zA-Z]{2}$")
                ? countryPrefix
                : null;
    }

    @JsonIgnore
    public boolean isHasEstonianPersonalCode() {
        return ESTONIAN_PERSONAL_CODE_PREFIX.equalsIgnoreCase(getCountryPrefix());
    }

}
