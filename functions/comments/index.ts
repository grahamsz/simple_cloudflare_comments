
import type { PluginArgs } from "../../..";
import { parse } from 'cookie';

import { SimpleCloudflareCommentsUser } from "../../index.ts";

import { marked }  from 'marked';
import { format } from 'timeago.js';
import sanitizeHtml from 'sanitize-html';

export interface Env {
  // This indicates that we're expecting a d1 database to be bound to the COMMENTS object
  COMMENTS: D1Database;
}



// This is the main entry point for the worker, this will handle all requests to the /comments path
export const onRequest: PagesFunction<Env> = async (context) => {

  // We need to know the function root so we can apply the correct path to the various other requests
  // we put this in context.data so other places can easily access it
  context.data.functionRoot = context.functionPath.replace(/\/[^\/]*$/, "/");


  // Now we extract the user from the cookie using the HMAC signature specified in authCookieSecret
  const cookieHeader = parse(context.request.headers.get('Cookie') || '');

  if (cookieHeader[context.pluginArgs.authCookieName] != null) {
    // if we can successfully decode the cookie, we'll add the decoded user to context.data
    context.data.decodedUser = await SimpleCloudflareCommentsUser.getFromCookieString(cookieHeader[context.pluginArgs.authCookieName],context.pluginArgs.authCookieSecret);
  }

  if (context.request.method == "GET") {
    // GET requests return a thread of comments
    return getCommentThread(context);
  }
  if (context.request.method == "POST") {
    // POST requests add a comment to the thread
    return addNewComment(context);
  }
  // We don't support any other methods
  return new Response("Method not allowed", { status: 405  });
}


// This function reteives the comments from the database and renders the HTML
async function getCommentThread(context) {

  // The reference is the path of the page we're commenting on
  var referer = context.request.headers.get("referer");

  var refererUrl = null;
  if (referer) {
    // we parse the referer to get a URL object and store it in context.data
    context.data.refererUrl = new URL(referer);
  } else
  {
    return new Response("Comments threads require a referer be set", { status: 400 });
  }


  try {
    // We use the d1 library to query the database
    // We use the referer pathname as the reference for the comments
    
    var sql = `SELECT comments.*,users.*, threads.url
                FROM comments 
                INNER JOIN users ON comments.user_id = users.user_id
                INNER JOIN threads ON comments.thread_id = threads.thread_id
      WHERE threads.url = ? ORDER BY ifnull(in_response_to_comment_id,comment_id), timestamp`;
    var results = await context.env.COMMENTS.prepare(sql).bind(context.data.refererUrl.pathname).all();
    context.data.comments = results.results;

  } catch (e) {
    return new Response("Error fetching the comments from the database: " + e, { status: 500 });  
  }

  // We use the getCommentsElement function to render the HTML
  var comments = await getCommentsElement(context);
  return new Response(comments, { status: 200 });
}

async function getCommentsElement(context) 
{
  // This is our string buffer for the resultant thread
  var commentsElement = "";
  var sqlResultSet = context.data.comments;

  commentsElement += `<div class="scc_thread">`;

  if (sqlResultSet.length > 0) {
    commentsElement += `<h4>There are ${sqlResultSet.length} comments.</h4>\n`;
  } else {
    commentsElement += `<h4>Nobdoy has commented yet.</h4>\n`;
  }

  commentsElement+= ` <div class="scc_links"><a href="#scc-${context.data.decodedUser ? "reply" : "login"}">Add a Comment</a></div>`;

  var lastCommentId;
  sqlResultSet.forEach((row) => {
    if ((lastCommentId) && (lastCommentId != (row.in_response_to_comment_id ?? row.comment_id))) {
      commentsElement += getAddCommentElement(context, lastCommentId)
    }
    commentsElement += getCommentElement(context, row);
    lastCommentId = row.in_response_to_comment_id ?? row.comment_id;
  });

  if (lastCommentId) {
    // This adds a reply box for the last comment
    commentsElement += getAddCommentElement(context, lastCommentId)
  }

  // and finally for the whole thread.
  commentsElement += getAddCommentElement(context, null)

  commentsElement += `</div">`;



  return commentsElement;

}

function getCommentElement(context, sqlResult) {

console.log(sanitizeHtml("<img src=x onerror=alert('img') />"));
console.log(sanitizeHtml("console.log('hello world')"));
console.log(sanitizeHtml("<script>alert('hello world')</script>"));
  var addedClass = "";
  var replyToId = "scc-" + (context.data.decodedUser ? "reply" : "login") + "-" + sqlResult.comment_id;
  if (sqlResult.in_response_to_comment_id) {
    // We support one level of indentation and since the comments are sorted correctly by the database
    // we can cheat here!
    addedClass = "scc_indent1"
    replyToId = "scc-" + (context.data.decodedUser ? "reply" : "login") + "-" + sqlResult.in_response_to_comment_id;
  }

  //console.log(Sanitize(marked.parse(`<img src="x" onerror="alert('not happening')">`), Sanitize::Config::RELAXED));

  return `
  <div class="scc_comment ${addedClass}" id="scc-comment-${sqlResult.comment_id}"  >
      <div class="scc_img"> <img src="${sqlResult.picture_url}"></div>
      <div class="scc_time">${format(sqlResult.timestamp)}</div>
      <div class="scc_text"><p>${sqlResult.sanitized_comment}</p></div>
      <div class="scc_author">${sqlResult.first_name}</div>
      <div class="scc_links"><a href="#${replyToId}">Reply</a></div>

  </div>`;

}

function getAddCommentElement(context, replyToCommentId) {
  var addedClass = "";
  var addedInputElement="";
  var replyToId;

  if (context.data.decodedUser) {
    replyToId = "scc-reply";
    if (replyToCommentId) {

      addedClass = "scc_indent1"
      replyToId = "scc-reply-" + replyToCommentId;
      addedInputElement = `<input type="hidden" name="in_response_to" value="${replyToCommentId}"/>`;
    }


    var logOutLink = context.data.functionRoot + "auth?logout=1&url=" + encodeURIComponent(context.request.headers.get("referer"));
    var submitLink = context.data.functionRoot + "comments";
    return `    <form action="${submitLink}" method="post">
  <div class="scc_comment scc_compose ${addedClass}" id="${replyToId}">
    ${addedInputElement}
    <input type="hidden" name="url" value="${context.data.refererUrl.pathname}"/>
    <input type="hidden" name="return_url" value="${context.data.refererUrl}"/>
    <div class="scc_img"> <img src=" ${context.data.decodedUser.pictureUrl}"></div>
    <div class="scc_time"></div>
    <div class="scc_text"><textarea name="comment" placeholder="Your comment here\nLimited _markdown_ is supported."></textarea></div> 
    <div class="scc_author">Posting as Graham (<a href="${logOutLink}">logout</a>)</div>
    <div class="scc_links"><a href="#" class="submit">Cancel</a><input type="submit"/></div>
    
  </div></form>`;

  } else {
    replyToId = "scc-login";
    if (replyToCommentId) {

      addedClass = "scc_indent1"
      replyToId = "scc-login-" + replyToCommentId;
    }

    // get the referrer URL

    const returnUrl = context.request.headers.get("referer") + "#scc-reply" + (replyToCommentId ? "-" + replyToCommentId : "");

    var googleSignIn = context.data.functionRoot + "auth?redirect=google&url=" + encodeURIComponent(returnUrl);
    return `
  <div class="scc_comment scc_login ${addedClass}" id="${replyToId}">
    <div class="scc_img scc_no_photo"> <icon></icon></div>
    <div class="scc_time"></div>
    <div class="scc_text"><a href="${googleSignIn}"><img src="https://developers.google.com/static/identity/images/btn_google_signin_light_normal_web.png"  alt="Sign in with Google"></a></div> 
    <div class="scc_author">Please sign in to post</div>
    <div class="scc_links"></div>
  </div>`;
  }
}

// This function handles the POST request to add a comment
async function addNewComment(context) {

  var request = context.request;

  // The webapp shouldn't let us get here without a user, but just in case
  if (context.data.decodedUser==null)  
  {
    return new Response("Invalid cookie", {status:401});
  }

  // get form parameters
  const formData = await request.formData();

  // get everything we need from the form
  const comment = formData.get("comment");
  const url =   formData.get("url");

  var inResponseTo = null;
  if (formData.get("in_response_to")) {
    inResponseTo = formData.get("in_response_to");
 }

  // load the thread by url
  var thread = await context.env.COMMENTS.prepare(`SELECT * from threads where url=?`).bind(url).all();

  if (thread.results.length==0) 
  {
    // if this thread doesn't exist, we'll need to insert it here
    await context.env.COMMENTS.prepare(`INSERT INTO threads (url) VALUES (?)`).bind(url).run();
  
    // now we can get the thread id (note in dev this is returned from the previous state, but in prod that comes back as null)
    thread = await context.env.COMMENTS.prepare(`SELECT * from threads where url=?`).bind(url).all();

  } 
  var threadId = thread.results[0].thread_id;  
  

  // now insert into database
  await context.env.COMMENTS.prepare(`INSERT INTO comments (user_id, thread_id, comment, sanitized_comment, timestamp, in_response_to_comment_id) VALUES (?, ?, ?, ?,?,?)`).bind(context.data.decodedUser.userId, threadId, comment,sanitizeHtml(marked.parse(comment)), Date.now(),inResponseTo).run();

  // we need a second query to get the comment id back
  var commentId = await context.env.COMMENTS.prepare(`SELECT max(comment_id) comment_id from comments where thread_id=?`).bind(threadId).all();

  // build a redirect url that will target the newly added comment, so it flashes with CSS
  const redirectUrl = new URL( formData.get("return_url")  + "#scc-comment-" +commentId.results[0].comment_id );
  var redirectResponse = Response.redirect(redirectUrl.toString(), 302);
  return redirectResponse;
}
