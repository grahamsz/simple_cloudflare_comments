
import type { PluginArgs } from "../..";
import { parse } from 'cookie';


import {
  github, google
} from "worker-auth-providers";
import { TokenError } from "worker-auth-providers/src/utils/errors";

export interface Env {
  COMMENTS: D1Database;
}




type cloudflareSimpleCommentsAuthFunction<
  Params extends string = any,
  Data extends Record<string, unknown> = Record<string, unknown>
> = PagesPluginFunction<Env, Params, Data, PluginArgs>;


const COOKIE_NAME = "cloudflare_comments_auth";


export const onRequest: PagesFunction<Env> = async (context) => {

  var request = context.request;
 // console.log("My env is " + JSON.stringify(context.env));
  const cookie = parse(request.headers.get('Cookie') || '');




  //console.log(JSON.stringify(results));
/*
  if (cookie[COOKIE_NAME] != null) {
    // Respond with the cookie value
    return new Response(cookie[COOKIE_NAME]);
  }
*/




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
          options: { clientId: "484015825698-jo5sr10ca5eiavcicakokce8q841v8el.apps.googleusercontent.com", clientSecret: "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", redirectUrl: "https://lvh.me:8788/auth" },
          request: request


        });
        console.log("about to query for user");

        // We'll have thrown by this point if the google login isn't valid
        var matchingUser = await context.env.COMMENTS.prepare(`SELECT * from users where auth_provider='google' and auth_provider_id=?`).bind(providerUser.id).all();

        console.log("matching user is " + JSON.stringify(matchingUser));

        if (matchingUser.results.length==0) {
          // We need to create a new user
          var insertResult = await context.env.COMMENTS.prepare(`INSERT INTO users (auth_provider, auth_provider_id, username, first_name, last_name, picture_url) VALUES ('google',?,?,?,?,?)`)
          .bind(providerUser.id, providerUser.email, providerUser.given_name, providerUser.family_name, providerUser.picture).run();

          console.log("Inserted ", insertResult);

        }


        var redirectUrl = new URL(stateParams.get("url"));
        redirectUrl.searchParams.set("cache_break", (Math.random() + 1).toString(36).substring(2));

        var redirectResponse = Response.redirect(redirectUrl.toString(), 302);
        redirectResponse.headers.set("Set-Cookie", `cloudflare_comments_auth=${providerUser.id}; Path=/; HttpOnly; SameSite=Lax;`);
        return redirectResponse;
      
     } catch ( e) {

      if (e instanceof TokenError)
      {
         return new Response("Google auth failed: " + e);
      } 
      else
      {
        throw e;
      }
     }

    }
  }

  if (searchParams.get("redirect") == "google") {
    console.log("creating google redirect")

    var state = "callback=google&url=" + encodeURI(searchParams.get("url"));
    var a = await google.redirect({ options: { clientId: "484015825698-jo5sr10ca5eiavcicakokce8q841v8el.apps.googleusercontent.com", state: state, clientSecret: "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", redirectUrl: "https://lvh.me:8788/auth" } });
    return Response.redirect(a);
  }

  return new Response("No action specified");



}

