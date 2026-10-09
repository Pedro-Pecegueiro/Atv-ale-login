package br.com.jurishome.auth.web;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import br.com.jurishome.auth.domain.Role;
import br.com.jurishome.auth.domain.UserAccount;
import br.com.jurishome.auth.dto.AdminUserUpdateForm;
import br.com.jurishome.auth.exception.BusinessException;
import br.com.jurishome.auth.service.TwoFactorService;
import br.com.jurishome.auth.service.UserAccountService;
import jakarta.validation.Valid;

@Controller
@RequestMapping("/admin/usuarios")
public class AdminUserController {

    private final UserAccountService userService;
    private final TwoFactorService twoFactorService;

    public AdminUserController(UserAccountService userService, TwoFactorService twoFactorService) {
        this.userService = userService;
        this.twoFactorService = twoFactorService;
    }

    @GetMapping
    public String list(Model model) {
        model.addAttribute("users", userService.findAll());
        return "admin/users";
    }

    @GetMapping("/{id}/editar")
    public String edit(@PathVariable String id, Model model) {
        UserAccount account = userService.findById(id);
        if (!model.containsAttribute("adminUserUpdateForm")) {
            AdminUserUpdateForm form = new AdminUserUpdateForm();
            form.setRoles(account.getRoles());
            form.setEnabled(account.isEnabled());
            model.addAttribute("adminUserUpdateForm", form);
        }
        model.addAttribute("user", account);
        model.addAttribute("allRoles", Role.values());
        return "admin/user-edit";
    }

    @PostMapping("/{id}")
    public String update(
        @PathVariable String id,
        @Valid @ModelAttribute AdminUserUpdateForm adminUserUpdateForm,
        BindingResult bindingResult,
        Principal principal,
        Model model,
        RedirectAttributes redirectAttributes
    ) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("user", userService.findById(id));
            model.addAttribute("allRoles", Role.values());
            return "admin/user-edit";
        }
        try {
            userService.updateByAdmin(id, adminUserUpdateForm, principal.getName());
            redirectAttributes.addFlashAttribute("success", "Usuario atualizado com seguranca.");
            return "redirect:/admin/usuarios";
        } catch (BusinessException ex) {
            bindingResult.reject("update", ex.getMessage());
            model.addAttribute("user", userService.findById(id));
            model.addAttribute("allRoles", Role.values());
            return "admin/user-edit";
        }
    }

    @PostMapping("/{id}/desbloquear")
    public String unlock(@PathVariable String id, RedirectAttributes redirectAttributes) {
        userService.unlock(id);
        redirectAttributes.addFlashAttribute("success", "Bloqueio e tentativas falhas removidos.");
        return "redirect:/admin/usuarios";
    }

    @PostMapping("/{id}/2fa/resetar")
    public String resetTwoFactor(
        @PathVariable String id,
        Principal principal,
        RedirectAttributes redirectAttributes
    ) {
        UserAccount account = userService.findById(id);
        if (account.getUsername().equals(principal.getName())) {
            redirectAttributes.addFlashAttribute("error", "Voce nao pode redefinir seu proprio autenticador por esta tela.");
            return "redirect:/admin/usuarios";
        }
        twoFactorService.reset(id);
        redirectAttributes.addFlashAttribute("success", "Autenticador do usuario redefinido.");
        return "redirect:/admin/usuarios";
    }

    @PostMapping("/{id}/excluir")
    public String delete(
        @PathVariable String id,
        Principal principal,
        RedirectAttributes redirectAttributes
    ) {
        try {
            userService.deleteByAdmin(id, principal.getName());
            redirectAttributes.addFlashAttribute("success", "Usuario excluido.");
        } catch (BusinessException ex) {
            redirectAttributes.addFlashAttribute("error", ex.getMessage());
        }
        return "redirect:/admin/usuarios";
    }
}
