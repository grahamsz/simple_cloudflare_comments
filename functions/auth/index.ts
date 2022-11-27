
import type { PluginArgs } from "../..";
import { parse } from 'cookie';

import { SimpleCloudflareCommentsUser } from "../../index.ts";

import {
  github, google
} from "worker-auth-providers";
import { TokenError } from "worker-auth-providers/src/utils/errors";

export interface Env {
  COMMENTS: D1Database;
}





const COOKIE_NAME = "cloudflare_comments_auth";


export const onRequest:  PagesFunction<Env> = async (context) => {


  var request = context.request;
  console.log("My env is " + JSON.stringify(context.env));
  const cookie = parse(request.headers.get('Cookie') || '');



  const { searchParams } = new URL(request.url);


  const stateParamsString = searchParams.get('state');

  if (stateParamsString) {
    console.log("have state params");

    const stateParams = new URLSearchParams(stateParamsString);

    if (stateParams.get("callback") == "google") {

      // If we got here then we got a redirect back from google with the completed user locin

      // Next we have to confirm that the request really came from google
      try {
        const { user: providerUser } = await google.users({
          options: { clientId: "484015825698-jo5sr10ca5eiavcicakokce8q841v8el.apps.googleusercontent.com", clientSecret: "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", redirectUrl:getRedirectUrl(request)  },
          request: request


        });
        console.log("about to query for user");

        // We'll have thrown by this point if the google login isn't valid
        var matchingUser = await context.env.COMMENTS.prepare(`SELECT * from users where auth_provider='google' and auth_provider_id=?`).bind(providerUser.id).all();

        console.log("matching user is " + JSON.stringify(matchingUser));
        var userId = 0; 

        if (matchingUser.results.length==0) {
          // We need to create a new user
          var insertResult = await context.env.COMMENTS.prepare(`INSERT INTO users (auth_provider, auth_provider_id, username, first_name, last_name, picture_url) VALUES ('google',?,?,?,?,?)`)
          .bind(providerUser.id, providerUser.email, providerUser.given_name, providerUser.family_name, providerUser.picture).run();


          // lastRowId appears unset in the cloudflare worker environment
          matchingUser = await context.env.COMMENTS.prepare(`SELECT * from users where auth_provider='google' and auth_provider_id=?`).bind(providerUser.id).all();


        }
        userId = matchingUser.results[0].user_id;
        

        var userObject =new SimpleCloudflareCommentsUser(userId, providerUser.email, "google",providerUser.id, providerUser.picture,  providerUser.given_name, providerUser.family_name,false);

        console.log(userObject);
        var cookieSting = await userObject.getSignedCookieString();

        var redirectUrl = new URL(stateParams.get("url"));
       // redirectUrl.searchParams.set("cache_break", (Math.random() + 1).toString(36).substring(2));


       return new Response("Redirecting back to site", {
        status: 302,
        headers: {
          'Set-Cookie': `cloudflare_comments_auth=${cookieSting}; Path=/;  SameSite=Lax;`,
          'Location': redirectUrl.toString()
        }
      });

      

     } catch ( e) {

      if (e instanceof TokenError)
      {
         return new Response("Google auth failed: " + e);
      } 
      else
      {
        return new Response("Error " + e);
      }
     }

    }
  }

  if (searchParams.get("redirect") == "google") {
    try{
          
    console.log("creating google redirect")

    var state = "callback=google&url=" + encodeURI(searchParams.get("url"));

    var a = await google.redirect({ options: { clientId: "484015825698-jo5sr10ca5eiavcicakokce8q841v8el.apps.googleusercontent.com", state: state, clientSecret: "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",  redirectUrl:  getRedirectUrl(request) } });
   

    return new Response(a, { status: 302, headers: { location: a } });

    } catch (e) { 
      return new Response("Google auth failed: " + e);
    }
  }

  return new Response("No action specified");



}

function getRedirectUrl(request)
{
  var auth = new URL(request.url);

    auth.search = "";   // remove any search parameters from our return adddress
    auth.pathname = "/auth";  // set the path to our auth handler
    return auth.toString().trim();
}