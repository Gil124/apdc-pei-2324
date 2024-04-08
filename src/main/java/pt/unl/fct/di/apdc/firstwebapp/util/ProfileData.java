package pt.unl.fct.di.apdc.firstwebapp.util;

public class ProfileData {

    public String password, newPassword;
    public String role;
    public Boolean state;
    public String phoneNumber;
    public String email;

    public ProfileData() { }

    public ProfileData(String password, String newPassword, String role, Boolean state, String phoneNumber, String email) {
        this.password = password;
        this.newPassword = newPassword;
        this.role = role;
        this.state = state;
        this.phoneNumber = phoneNumber;
        this.email = email;
    }

}
