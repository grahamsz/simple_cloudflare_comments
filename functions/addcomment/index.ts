
import type { PluginArgs } from "../..";
import { parse } from 'cookie';

import { SimpleCloudflareCommentsUser } from "../../index.ts";

export interface Env {
  COMMENTS: D1Database;
}




export const onRequest: PagesFunction<Env> = async (context) => {

  var request = context.request;

  if (request.method!="POST")
  {
    return new Response("Method not allowed", {status:405});
  }
  
  
 // console.log("My env is " + JSON.stringify(context.env));
  const cookie = parse(request.headers.get('Cookie') || '');

  if (cookie["cloudflare_comments_auth"] != null) {
    var decodedUser = await SimpleCloudflareCommentsUser.getFromCookieString(cookie["cloudflare_comments_auth"]);
    // Respond with the cookie value

    if (decodedUser==null)  
    {
      return new Response("Invalid cookie", {status:401});
    }

  // get form parameters
  const formData = await request.formData();
  console.log(formData);
  const comment = formData.get("comment");
  const url =   formData.get("url");


  // load the thread by url
  var thread = await context.env.COMMENTS.prepare(`SELECT * from threads where url=?`).bind(url).all();

  if (thread.results.length==0) 
  {
    //insert thread
    var insertResultThread = await context.env.COMMENTS.prepare(`INSERT INTO threads (url) VALUES (?)`).bind(url).run();
  
    thread = await context.env.COMMENTS.prepare(`SELECT * from threads where url=?`).bind(url).all();

  } 
 var   threadId = thread.results[0].thread_id;  
  

  console.log("thread id is " + threadId);
  console.log("user id is " + decodedUser.userId);
  // now insert into database
  var insertResult = await context.env.COMMENTS.prepare(`INSERT INTO comments (user_id, thread_id, comment, timestamp) VALUES (?, ?, ?,date())`).bind(decodedUser.userId, threadId, comment).run();
  console.log("insert result is " + JSON.stringify(insertResult));

  var redirectUrl = new URL( formData.get("return_url")  );

  //redirectUrl.searchParams.set("cache_break", (Math.random() + 1).toString(36).substring(2));

  var redirectResponse = Response.redirect(redirectUrl.toString(), 302);
  return redirectResponse;
}
};