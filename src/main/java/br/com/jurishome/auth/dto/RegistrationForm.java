package br.com.jurishome.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class RegistrationForm {

    @NotBlank(message = "Informe o nome completo.")
    @Size(min = 3, max = 100, message = "O nome completo deve ter entre 3 e 100 caracteres.")
    private String fullName;

    @NotBlank(message = "Informe o nome de usuario.")
    @Size(min = 3, max = 30, message = "Use entre 3 e 30 caracteres.")
    @Pattern(regexp = "^[A-Za-z0-9._-]+$", message = "Use apenas letras, numeros, ponto, hifen ou sublinhado.")
    private String username;

    @NotBlank(message = "Informe o e-mail.")
    @Email(message = "Informe um e-mail valido.")
    @Size(max = 120, message = "O e-mail deve ter no maximo 120 caracteres.")
    private String email;

    @NotBlank(message = "Informe a senha.")
    @Size(min = 12, max = 72, message = "A senha deve ter entre 12 e 72 caracteres.")
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$",
        message = "Use ao menos uma letra minuscula, uma maiuscula, um numero e um simbolo."
    )
    private String password;

    @NotBlank(message = "Confirme a senha.")
    @Size(max = 72, message = "A confirmacao deve ter no maximo 72 caracteres.")
    private String confirmPassword;

    public String getFullName() { return fullName; }
    public void setFullName(String fullName) { this.fullName = fullName; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getConfirmPassword() { return confirmPassword; }
    public void setConfirmPassword(String confirmPassword) { this.confirmPassword = confirmPassword; }
}
