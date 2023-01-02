package ee.eesti.authentication.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;
import rig.commons.aop.Timed;

import java.util.Collections;

/**
 * Controller containing endpoints dealing with user info
 */
@Controller
@Slf4j
@Timed
public class UserInfoController {


    public static final String USER_INFO_URL = "/userinfo";


    /**
     *
     * @param authentication auth details of the user
     * @return contains mapping : key - "userinfo", value : authentication details
     */
    @GetMapping(USER_INFO_URL)
    public ModelAndView userInfo(Authentication authentication) {

        log.info("loggedIn: {}", authentication);

        return new ModelAndView(
                "userinfo",
                Collections.singletonMap(
                        "userInfo",
                        authentication.getDetails()));
    }

}
