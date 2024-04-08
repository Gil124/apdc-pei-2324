package pt.unl.fct.di.apdc.firstwebapp.util;

public class RegisterData {
    public String username, password, secondPassword, name, email, phoneNumber;

    public String role;
    public boolean state;

    public RegisterData() {

    }

    public RegisterData(String username, String password, String secondPassword, String name, String email, String phoneNumber) {
        this.username = username;
        this.password = password;
        this.secondPassword = secondPassword;
        this.name = name;
        this.email = email;
        this.phoneNumber = phoneNumber;

        role = "user";
        state = false;
    }

    public boolean isDatavalid() {
        String regex = "^[\\w!#$%&'+/=?^`{|}~-]+(?:\\.[\\w!#$%&'+/=?^`{|}~-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$";
        return email.matches(regex) && isPasswordValid() && password.equals(secondPassword);
    }

    public boolean isPasswordValid() {
        return password.length() >=6 && password.matches(".*[A-Z].*") && password.matches(".*[a-z].*") && password.matches(".*[!@#$%^&()*_+-=].*") && password.matches(".*[0-9].*");
    }
}
