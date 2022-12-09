import simpleCloudFlareComments from "pages-plugin-simple-cloudflare-comments";



const hello = async ({ next }) => {
  const response = await next();
  if (response.headers.get("location"))
  {
    // THis is horribly hacky, but in production we seem to lose our 302 response codes and it breaks everything
    return new Response(null, {status:302, headers:response.headers});
  }
  return response;
};



export const onRequest: PagesFunction[] = [
  
  hello,
  simpleCloudFlareComments({
    googleClientId: "xxxxx",
    googleClientSecret: "xxxxx",

    authCookieName: "comments_cookie",
    authCookieSecret: "xxxx_change_this_to_any_random_secret_string",
    

  })
];