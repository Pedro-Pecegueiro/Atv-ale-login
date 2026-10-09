package br.com.jurishome.auth.web;

import java.security.Principal;

import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import br.com.jurishome.auth.security.TwoFactorSession;
import br.com.jurishome.auth.service.TwoFactorService;
import br.com.jurishome.auth.service.UserAccountService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Controller
public class TwoFactorController {

    private static final int MAX_ATTEMPTS = 3;

    private final TwoFactorService twoFactorService;
    private final UserAccountService userService;

    public TwoFactorController(TwoFactorService twoFactorService, UserAccountService userService) {
        this.twoFactorService = twoFactorService;
        this.userService = userService;
    }

    @GetMapping("/2fa/configurar")
    public String setup(Principal principal, Model model) {
        if (twoFactorService.isEnabled(principal.getName())) {
            return "redirect:/2fa/verificar";
        }
        model.addAttribute("secret", twoFactorService.prepareEnrollment(principal.getName()));
        return "auth/two-factor-setup";
    }

    @GetMapping(value = "/2fa/qr", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> qrCode(Principal principal) {
        return ResponseEntity.ok()
            .cacheControl(CacheControl.noStore())
            .contentType(MediaType.IMAGE_PNG)
            .body(twoFactorService.qrCode(principal.getName()));
    }

    @PostMapping("/2fa/configurar")
    public String confirmSetup(
        @RequestParam String code,
        Principal principal,
        HttpServletRequest request,
        Model model,
        RedirectAttributes redirectAttributes
    ) {
        if (!twoFactorService.activate(principal.getName(), code)) {
            model.addAttribute("secret", twoFactorService.prepareEnrollment(principal.getName()));
            model.addAttribute("error", "Codigo invalido.");
            return "auth/two-factor-setup";
        }
        finishAuthentication(request, principal.getName());
        redirectAttributes.addFlashAttribute("success", "Autenticador configurado com sucesso.");
        return "redirect:/dashboard";
    }

    @GetMapping("/2fa/verificar")
    public String verifyPage(Principal principal) {
        if (!twoFactorService.isEnabled(principal.getName())) {
            return "redirect:/2fa/configurar";
        }
        return "auth/two-factor-verify";
    }

    @PostMapping("/2fa/verificar")
    public String verifyCode(
        @RequestParam String code,
        Principal principal,
        HttpServletRequest request,
        Model model
    ) {
        if (twoFactorService.verify(principal.getName(), code)) {
            finishAuthentication(request, principal.getName());
            return "redirect:/dashboard";
        }

        userService.recordLoginFailure(principal.getName());
        HttpSession session = request.getSession();
        int attempts = session.getAttribute(TwoFactorSession.FAILED_ATTEMPTS) instanceof Integer value
            ? value + 1
            : 1;
        if (attempts >= MAX_ATTEMPTS) {
            SecurityContextHolder.clearContext();
            session.invalidate();
            return "redirect:/login?error";
        }
        session.setAttribute(TwoFactorSession.FAILED_ATTEMPTS, attempts);
        model.addAttribute("error", "Codigo invalido.");
        return "auth/two-factor-verify";
    }

    private void finishAuthentication(HttpServletRequest request, String username) {
        request.changeSessionId();
        HttpSession session = request.getSession();
        session.setAttribute(TwoFactorSession.VERIFIED, true);
        session.removeAttribute(TwoFactorSession.FAILED_ATTEMPTS);
        userService.recordLoginSuccess(username);
    }
}
