<?php
include "../../config/security.php";
include "../../incl/lib/connection.php";
require "../../incl/lib/exploitPatch.php";
require "../../incl/lib/generatePass.php";
require "../../incl/lib/TimeoutCheck.php";
require_once "../../incl/lib/Captcha.php";

if(!isset($preactivateAccounts)){
	$preactivateAccounts = true;
}



// here begins the checks
if(!empty($_POST["username"]) AND !empty($_POST["email"]) AND !empty($_POST["repeatemail"]) AND !empty($_POST["password"]) AND !empty($_POST["repeatpassword"])){
	// catching all the input
	$username = ExploitPatch::remove($_POST["username"]);
	$password = ExploitPatch::remove($_POST["password"]);
	$repeat_password = ExploitPatch::remove($_POST["repeatpassword"]);
	$email = ExploitPatch::remove($_POST["email"]);
	$repeat_email = ExploitPatch::remove($_POST["repeatemail"]);
	if(strlen($username) < 3){
		// choose a longer username
		echo '<body style="background-color:black;color:white;">Username should be more than 3 characters.<br>';
		header("Refresh:4");
	}elseif(strlen($password) < 6){
		// just why did you want to give a short password? do you wanna be hacked?
		echo '<body style="background-color:black;color:white;">-color:grey;">Password should be more than 6 characters.<br>';
		header("Refresh:4");
	}else{
		// this checks if there is another account with the same username as your input
		$query = $db->prepare("SELECT count(*) FROM accounts WHERE userName LIKE :userName");
		$query->execute([':userName' => $username]);
		$registred_users = $query->fetchColumn();
		if($registred_users > 0){
			// why did you want to make a new account with the same username as someone else's
			echo '<body style="background-color:black;color:white;">Username already taken.<br>';
		}else{
			if($password != $repeat_password){
				// this is when the passwords do not match
				echo '<body style="background-color:black;color:white;">Passwords do not match.<br>';
				header("Refresh:4");
			}elseif($email != $repeat_email){
				// this is when the emails dont match
				echo '<body style="background-color:black;color:white;">Emails do not match.<br>';
				header("Refresh:4");
			}else{
				// hashing your password and registering your account
                TimeoutCheck::CheckTimeout(-705);
				$hashpass = password_hash($password, PASSWORD_DEFAULT);
				$query2 = $db->prepare("INSERT INTO accounts (userName, password, email, registerDate, isActive, gjp2)
				VALUES (:userName, :password, :email, :time, :isActive, :gjp2)");
				$query2->execute([':userName' => $username, ':password' => $hashpass, ':email' => $email,':time' => time(), ':isActive' => $preactivateAccounts ? 1 : 0, ':gjp2' => GeneratePass::GJP2hash($password)]);
				// there you go, you are registered.
				$activationInfo = $preactivateAccounts ? "No e-mail verification required, you can login." : "<a href='activateAccount.php'>Click here to activate account.</a>";
				echo "<body style='background-color:black;'>Account registred. $activationInfo <a href='..'>Go back to tools</a></body>";
			}
		}
	}
}else{
	// this is given when we dont have an input
	echo '<h2>Register Account</h2><br><body style="background-color:black;color:white;"><form action="registerAccount.php" method="post">Username: <input type="text" name="username" maxlength=15><br>Password: <input type="password" name="password" maxlength=20><br>Repeat Password: <input type="password" name="repeatpassword" maxlength=20><br>Fake Email: <input type="email" name="email" maxlength=50><br>Repeat Fake Email: <input type="email" name="repeatemail" maxlength=50><br>';
	Captcha::displayCaptcha();
	echo '<input type="submit" value="Register"></form></body>';

}
?>