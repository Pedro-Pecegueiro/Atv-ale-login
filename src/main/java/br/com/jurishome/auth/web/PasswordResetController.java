package br.com.jurishome.auth.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import br.com.jurishome.auth.dto.PasswordResetForm;
import br.com.jurishome.auth.dto.EmailRequestForm;
import br.com.jurishome.auth.exception.BusinessException;
import br.com.jurishome.auth.service.PasswordResetService;
import jakarta.validation.Valid;

@Controller
public class PasswordResetController {

    private final PasswordResetService passwordResetService;

    public PasswordResetController(PasswordResetService passwordResetService) {
        this.passwordResetService = passwordResetService;
    }

    @GetMapping("/senha/esqueci")
    public String forgotPassword(Model model) {
        if (!model.containsAttribute("emailRequestForm")) {
            EmailRequestForm form = new EmailRequestForm();
            Object requestedEmail = model.asMap().get("requestedEmail");
            if (requestedEmail instanceof String email) {
                form.setEmail(email);
            }
            model.addAttribute("emailRequestForm", form);
        }
        return "auth/forgot-password";
    }

    @PostMapping("/senha/esqueci")
    public String requestReset(
        @Valid @ModelAttribute EmailRequestForm emailRequestForm,
        BindingResult bindingResult,
        RedirectAttributes redirectAttributes
    ) {
        if (bindingResult.hasErrors()) {
            return "auth/forgot-password";
        }
        PasswordResetService.Delivery delivery = passwordResetService.request(emailRequestForm.getEmail());
        redirectAttributes.addFlashAttribute(
            "success",
            "Se existir uma conta ativa para este e-mail, um link de recuperacao foi gerado."
        );
        redirectAttributes.addFlashAttribute("requestedEmail", emailRequestForm.getEmail());
        if (delivery.localResetUrl() != null) {
            redirectAttributes.addFlashAttribute("resetUrl", delivery.localResetUrl());
        }
        return "redirect:/senha/esqueci";
    }

    @GetMapping("/senha/redefinir")
    public String resetPassword(
        @RequestParam String token,
        Model model,
        RedirectAttributes redirectAttributes
    ) {
        try {
            passwordResetService.validate(token);
            if (!model.containsAttribute("passwordResetForm")) {
                PasswordResetForm form = new PasswordResetForm();
                form.setToken(token);
                model.addAttribute("passwordResetForm", form);
            }
            return "auth/reset-password";
        } catch (BusinessException ex) {
            redirectAttributes.addFlashAttribute("error", ex.getMessage());
            return "redirect:/senha/esqueci";
        }
    }

    @PostMapping("/senha/redefinir")
    public String resetPassword(
        @Valid @ModelAttribute PasswordResetForm passwordResetForm,
        BindingResult bindingResult,
        RedirectAttributes redirectAttributes
    ) {
        if (bindingResult.hasErrors()) {
            return "auth/reset-password";
        }
        try {
            passwordResetService.reset(
                passwordResetForm.getToken(),
                passwordResetForm.getPassword(),
                passwordResetForm.getConfirmPassword()
            );
            redirectAttributes.addFlashAttribute("success", "Senha redefinida. Entre com a nova senha.");
            return "redirect:/login";
        } catch (BusinessException ex) {
            bindingResult.reject("passwordReset", ex.getMessage());
            return "auth/reset-password";
        }
    }
}
