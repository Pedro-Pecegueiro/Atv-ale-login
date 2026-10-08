package br.com.jurishome.auth.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import br.com.jurishome.auth.domain.UserAccount;
import br.com.jurishome.auth.dto.EmailRequestForm;
import br.com.jurishome.auth.dto.RegistrationForm;
import br.com.jurishome.auth.exception.BusinessException;
import br.com.jurishome.auth.service.RegistrationVerificationService;
import br.com.jurishome.auth.service.UserAccountService;
import jakarta.validation.Valid;

@Controller
public class AuthController {

    private final UserAccountService userService;
    private final RegistrationVerificationService verificationService;

    public AuthController(
        UserAccountService userService,
        RegistrationVerificationService verificationService
    ) {
        this.userService = userService;
        this.verificationService = verificationService;
    }

    @GetMapping("/login")
    public String login() {
        return "auth/login";
    }

    @GetMapping("/cadastro")
    public String registration(Model model) {
        if (!model.containsAttribute("registrationForm")) {
            model.addAttribute("registrationForm", new RegistrationForm());
        }
        return "auth/register";
    }

    @PostMapping("/cadastro")
    public String register(
        @Valid @ModelAttribute RegistrationForm registrationForm,
        BindingResult bindingResult,
        RedirectAttributes redirectAttributes
    ) {
        if (bindingResult.hasErrors()) {
            return "auth/register";
        }
        try {
            UserAccount account = userService.register(registrationForm);
            RegistrationVerificationService.Delivery delivery = verificationService.issue(account);
            redirectAttributes.addFlashAttribute("success", "Cadastro realizado. Confirme seu e-mail para liberar o acesso.");
            redirectAttributes.addFlashAttribute("registeredEmail", account.getEmail());
            if (delivery.localVerificationUrl() != null) {
                redirectAttributes.addFlashAttribute("verificationUrl", delivery.localVerificationUrl());
            }
            return "redirect:/cadastro/pendente";
        } catch (BusinessException ex) {
            bindingResult.reject("registration", ex.getMessage());
            return "auth/register";
        }
    }

    @GetMapping("/cadastro/pendente")
    public String pendingRegistration(Model model) {
        if (!model.containsAttribute("emailRequestForm")) {
            EmailRequestForm form = new EmailRequestForm();
            Object registeredEmail = model.asMap().get("registeredEmail");
            if (registeredEmail instanceof String email) {
                form.setEmail(email);
            }
            model.addAttribute("emailRequestForm", form);
        }
        return "auth/registration-pending";
    }

    @GetMapping("/cadastro/confirmar")
    public String confirmRegistration(
        @RequestParam String token,
        RedirectAttributes redirectAttributes
    ) {
        try {
            verificationService.confirm(token);
            redirectAttributes.addFlashAttribute("success", "Cadastro confirmado. Voce ja pode entrar.");
            return "redirect:/login";
        } catch (BusinessException ex) {
            redirectAttributes.addFlashAttribute("error", ex.getMessage());
            return "redirect:/cadastro/pendente";
        }
    }

    @PostMapping("/cadastro/reenviar")
    public String resendConfirmation(
        @Valid @ModelAttribute EmailRequestForm emailRequestForm,
        BindingResult bindingResult,
        RedirectAttributes redirectAttributes
    ) {
        if (bindingResult.hasErrors()) {
            return "auth/registration-pending";
        }
        RegistrationVerificationService.Delivery delivery = verificationService.resend(emailRequestForm.getEmail());
        redirectAttributes.addFlashAttribute(
            "success",
            "Se existir um cadastro pendente para este e-mail, um novo link foi gerado."
        );
        redirectAttributes.addFlashAttribute("registeredEmail", emailRequestForm.getEmail());
        if (delivery.localVerificationUrl() != null) {
            redirectAttributes.addFlashAttribute("verificationUrl", delivery.localVerificationUrl());
        }
        return "redirect:/cadastro/pendente";
    }
}
