function setCookie(res, refresh_token) {
    // Set token in HTTP-only cookie
    res.cookie("refresh_token", refresh_token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 5 * 24 * 60 * 60 * 1000,
    });
  }
  
  export default setCookie;
  