package br.com.jurishome.auth.web;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import br.com.jurishome.auth.service.UserAccountService;

@Controller
public class HomeController {

    private final UserAccountService userService;

    public HomeController(UserAccountService userService) {
        this.userService = userService;
    }

    @GetMapping("/")
    public String index() {
        return "redirect:/login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Principal principal, Model model) {
        model.addAttribute("account", userService.findByLogin(principal.getName()));
        return "dashboard";
    }

    @GetMapping("/usuario")
    public String userArea() {
        return "areas/user";
    }

    @GetMapping("/moderador")
    public String moderatorArea() {
        return "areas/moderator";
    }

    @GetMapping("/acesso-negado")
    public String accessDenied() {
        return "error/403";
    }
}
