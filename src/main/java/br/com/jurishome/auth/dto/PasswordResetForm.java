package br.com.jurishome.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class PasswordResetForm {

    @NotBlank(message = "Link de recuperacao ausente.")
    @Size(max = 200, message = "Link de recuperacao invalido.")
    private String token;

    @NotBlank(message = "Informe a nova senha.")
    @Size(min = 12, max = 72, message = "A senha deve ter entre 12 e 72 caracteres.")
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$",
        message = "Use ao menos uma letra minuscula, uma maiuscula, um numero e um simbolo."
    )
    private String password;

    @NotBlank(message = "Confirme a nova senha.")
    @Size(max = 72, message = "A confirmacao deve ter no maximo 72 caracteres.")
    private String confirmPassword;

    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getConfirmPassword() { return confirmPassword; }
    public void setConfirmPassword(String confirmPassword) { this.confirmPassword = confirmPassword; }
}
