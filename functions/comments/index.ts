
import type { PluginArgs } from "../../..";
import { parse } from 'cookie';

import { SimpleCloudflareCommentsUser } from "../../index.ts";

import { marked } from 'marked';
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
    context.data.decodedUser = await SimpleCloudflareCommentsUser.getFromCookieString(cookieHeader[context.pluginArgs.authCookieName], context.pluginArgs.authCookieSecret);
  }

  if (context.request.method == "GET") {
    // GET requests return a thread of comments
    return getCommentThread(context);
  }
  if (context.request.method == "POST") {

    context.data.formData = await context.request.formData();

    // if comment_id is posted then this is an edit
    if (context.data.formData.get("comment_id")) {
      return editComment(context);
    }
    
  

    // POST requests add a comment to the thread
    return addNewComment(context);
  }
  // We don't support any other methods
  return new Response("Method not allowed", { status: 405 });
}


// This function reteives the comments from the database and renders the HTML
async function getCommentThread(context) {

  // The reference is the path of the page we're commenting on
  var referer = context.request.headers.get("referer");

  var refererUrl = null;
  if (referer) {
    // we parse the referer to get a URL object and store it in context.data
    context.data.refererUrl = new URL(referer);
  } else {
    return new Response("Comments threads require a referer be set", { status: 400 });
  }

  var promises = [];

  // We use the d1 library to query the database
  // We use the referer pathname as the reference for the comments

  var sql = `SELECT comments.*,users.*, threads.url
                FROM comments 
                INNER JOIN users ON comments.user_id = users.user_id
                INNER JOIN threads ON comments.thread_id = threads.thread_id
      WHERE threads.url = ? ORDER BY ifnull(in_response_to_comment_id,comment_id), timestamp`;
  promises.push(context.env.COMMENTS.prepare(sql).bind(context.data.refererUrl.pathname).all().then((sqlResultSet) => {
    context.data.comments = sqlResultSet.results;
  }));

  console.log("https://webmention.io/api/mentions.jf2?target=" + encodeURIComponent(context.data.refererUrl.toString()));
  // fetch the following URL and return a promise for the response
  promises.push(fetch("https://webmention.io/api/mentions.jf2?target=" + encodeURIComponent(context.data.refererUrl.toString()))
    .then(async response => {
      context.data.webmentions = await response.json();
      console.log(context.data.webmentions);
    }
    ));

  await Promise.all(promises);

  // convert the comments list to that the in_response_to_comment_id comments get added as collction to the parent comment

  var commentsById = {};
  context.data.comments.forEach((comment) => {
    commentsById[comment.comment_id] = comment;

    if (comment.in_response_to_comment_id) {
      if (!commentsById[comment.in_response_to_comment_id].replies) {
        commentsById[comment.in_response_to_comment_id].replies = [];
      }
      commentsById[comment.in_response_to_comment_id].replies.push(comment);

      // remove the child comment from the parent list
      context.data.comments = context.data.comments.filter((c) => c.comment_id != comment.comment_id);
    }
  });

  // extract all webmentions with a wm-property of like-of
  context.data.webmentionLikes = context.data.webmentions.children.filter((wm) => wm["wm-property"] == "like-of");
  context.data.webmentionReposts = context.data.webmentions.children.filter((wm) => wm["wm-property"] == "repost-of");

  // filter out all in-reply-to mentions and convert their published date to a timestamp
  context.data.webmentionReplies = context.data.webmentions.children.filter((wm) => wm["wm-property"] == "in-reply-to").map((wm) => {
    wm.timestamp = new Date(wm.published).getTime();
    wm.first_name = wm.author.name;
    wm.last_name = "";
    wm.wm_url = wm.url;
    wm.url = wm.author.url;

    wm.sanitized_comment = sanitizeHtml(wm.content.html);
    wm.picture_url = wm.author.photo;
    return wm;
  });

  // append the webmentions to the comments and sort by timestamp
  context.data.comments = context.data.comments.concat(context.data.webmentionReplies).sort((a, b) => a.timestamp - b.timestamp);

  // We use the getCommentsElement function to render the HTML
  var comments = await getCommentsElement(context);

  return new Response(comments, { status: 200 });
}

async function getCommentsElement(context) {
  // This is our string buffer for the resultant thread
  var commentsElement = "";
  var sqlResultSet = context.data.comments;

  commentsElement += `<div class="scc_thread">`;

  var totalComments = sqlResultSet.filter((comment) => comment.comment_id).reduce((total, comment) => 1 + total + (comment.replies ? comment.replies.length : 0), 0);
  var totalLikes = context.data.webmentionLikes.length;
  var totalReposts = context.data.webmentionReposts.length;
  var totalWebmentions = sqlResultSet.filter((comment) => comment.wm_url).length;

  // build a summary of the four totals
  var summary = [];
  if (totalComments > 0) {
    summary.push(`${totalComments} comment${totalComments > 1 ? "s" : ""}</span>`);
  }
  if (totalWebmentions > 0) {
    summary.push(`${totalWebmentions} webmention${totalWebmentions > 1 ? "s" : ""}</span>`);
  }

  if (totalLikes > 0) {
    summary.push(`${totalLikes} like${totalLikes > 1 ? "s" : ""}</span>`);
  }
  if (totalReposts > 0) {
    summary.push(`${totalReposts} repost${totalReposts > 1 ? "s" : ""}</span>`);
  }

  if (summary.length == 0) {
    commentsElement += "No comments yet. Post below or <a href=\"https://webmention.io/\">send a webmention</a>.";
  }
  else{
  commentsElement += `<div class="scc_summary">This post has ${summary.join(", ")}.</div>`;
  }



  if (totalLikes>0)
  {
    commentsElement += `<div class="scc_likes scc_reactions"><div class="scc_icon"><icon></icon></div>`;
    context.data.webmentionLikes.forEach((wm) => {
      commentsElement += `<a href="${wm.author.url}" class="scc_like" title="${wm.author.name} liked this"><img src="${wm.author.photo}" alt="${wm.author.name}  liked this" /></a>`;
    });
    commentsElement += `</div>`;
  }

  if (totalReposts>0)
  {
    commentsElement += `<div class="scc_reposts scc_reactions"><div class="scc_icon"><icon></icon></div>`;
    context.data.webmentionReposts.forEach((wm) => {
      commentsElement += `<a href="${wm.author.url}" class="scc_repost" title="${wm.author.name}  reposted this"><img src="${wm.author.photo}" alt="${wm.author.name}  reposted this" /></a>`;
    });
    commentsElement += `</div>`;
  }




  var lastCommentId;
  sqlResultSet.forEach((row) => {

    commentsElement += getCommentElement(context, row);
    // also add child comments
    if (row.replies) {
      row.replies.forEach((reply) => {
        commentsElement += getCommentElement(context, reply);
      });
    }


    if (row.comment_id) {
      commentsElement += getAddCommentElement(context, row.comment_id)
    }
  });



  // and finally for the whole thread.
  commentsElement += getAddCommentElement(context, null)

  commentsElement += ` <div class="scc_links"><a href="#scc-${context.data.decodedUser ? "reply" : "login"}">Add a Comment</a></div>`;
  commentsElement += `</div">`;



  return commentsElement;

}

function getCommentElement(context, sqlResult) {

  var addedClass = "";
  var links = [];
  var authorLink = "";

  var editable=false;

  
  if ((context.data.decodedUser) && (sqlResult.user_id==context.data.decodedUser.userId)  &&  (new Date().getTime() - sqlResult.timestamp < 600000))
  {
    editable=true;
  }

  var replyToId = "scc-" + (context.data.decodedUser ? "reply" : "login") + "-" + sqlResult.comment_id;
  if (sqlResult.in_response_to_comment_id) {
    // We support one level of indentation and since the comments are sorted correctly by the database
    // we can cheat here!
    addedClass = "scc_indent1"
    replyToId = "scc-" + (context.data.decodedUser ? "reply" : "login") + "-" + sqlResult.in_response_to_comment_id;
  }

  if (sqlResult.comment_id) {
    links.push(`<a class="scc_links_reply" href="#${replyToId}">Reply</a>`);
  }

  if (sqlResult.wm_url) {
    links.push(`<a class="scc_links_view_wm" href="${sqlResult.wm_url}">View Webmention</a>`);
  }

  if (editable)
  {
    var stillEditableForMinutes = Math.round((600000 - (new Date().getTime() - sqlResult.timestamp))/60000) + " minutes";
    links.push(`<a class="scc_links_edit" href="#scc-edit-${sqlResult.comment_id}">Edit (for ${stillEditableForMinutes})</a>`);
    links.push(`<a class="scc_links_cancel_edit" href="#scc-comment-${sqlResult.comment_id}">Cancel Edit</a>`);
    
    links.push(`<input class="scc_links_submit_edit"  value="Save Changes" type="submit"/>`)

  }
  // test if url is more than 5 chars long and starts with http or https    
  if (sqlResult.url && sqlResult.url.length > 5 && sqlResult.url.match(/^https?:\/\//)) {
    authorLink = `<br><a href="${sqlResult.url}">${sqlResult.url}</a>`;
  }

  var combinedComment = "";
  
  if (editable) { combinedComment += `
  <form action="${ context.data.functionRoot + "comments"}" method="post" class="scc_editable" id="scc-edit-${sqlResult.comment_id}">  
  <input type="hidden" name="comment_id" value="${sqlResult.comment_id}"/>
  <input type="hidden" name="url" value="${context.data.refererUrl.pathname}"/>
  <input type="hidden" name="return_url" value="${context.data.refererUrl}"/>`; }

  combinedComment+=  ` 
  <div class="scc_comment ${addedClass}" id="scc-comment-${sqlResult.comment_id}"  >
      <div class="scc_img"> <img src="${sqlResult.picture_url}"></div>
      <div class="scc_time">${format(sqlResult.timestamp)}</div>
      <div class="scc_text"><span>${sqlResult.sanitized_comment}</span>`;
      if (editable) { combinedComment += `<textarea name="comment">${sqlResult.comment}</textarea>`; }
      
      combinedComment+= `</div>
      <div class="scc_author">${sqlResult.first_name}${authorLink}</div>
      <div class="scc_links">${links.join("")}</div>

  </div>`;

  if (editable) { combinedComment += `</form>`; }
  return combinedComment;

}

function getAddCommentElement(context, replyToCommentId) {
  var addedClass = "";
  var addedInputElement = "";
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
    <div class="scc_links"><a href="#" class="submit">Cancel</a><input value="Post Comment" type="submit"/></div>
    
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
  if (context.data.decodedUser == null) {
    return new Response("Invalid cookie", { status: 401 });
  }

  // get form parameters
  const formData = context.data.formData;

  // get everything we need from the form
  const comment = formData.get("comment");
  const url = formData.get("url");

  var inResponseTo = null;
  if (formData.get("in_response_to")) {
    inResponseTo = formData.get("in_response_to");
  }

  // load the thread by url
  var thread = await context.env.COMMENTS.prepare(`SELECT * from threads where url=?`).bind(url).all();

  if (thread.results.length == 0) {
    // if this thread doesn't exist, we'll need to insert it here
    await context.env.COMMENTS.prepare(`INSERT INTO threads (url) VALUES (?)`).bind(url).run();

    // now we can get the thread id (note in dev this is returned from the previous state, but in prod that comes back as null)
    thread = await context.env.COMMENTS.prepare(`SELECT * from threads where url=?`).bind(url).all();

  }
  var threadId = thread.results[0].thread_id;


  // now insert into database
  await context.env.COMMENTS.prepare(`INSERT INTO comments (user_id, thread_id, comment, sanitized_comment, timestamp, in_response_to_comment_id) VALUES (?, ?, ?, ?,?,?)`).bind(context.data.decodedUser.userId, threadId, comment, sanitizeHtml(marked.parse(comment)), Date.now(), inResponseTo).run();

  // we need a second query to get the comment id back
  var commentId = await context.env.COMMENTS.prepare(`SELECT max(comment_id) comment_id from comments where thread_id=?`).bind(threadId).all();

  // build a redirect url that will target the newly added comment, so it flashes with CSS
  const redirectUrl = new URL(formData.get("return_url") + "#scc-comment-" + commentId.results[0].comment_id);
  var redirectResponse = Response.redirect(redirectUrl.toString(), 302);
  return redirectResponse;
}

// This function handles the POST request to add a comment
async function editComment(context) {

  var request = context.request;

  // The webapp shouldn't let us get here without a user, but just in case
  if (context.data.decodedUser == null) {
    return new Response("Invalid cookie", { status: 401 });
  }

  // get form parameters
  const formData = context.data.formData;

  // get everything we need from the form
  const comment = formData.get("comment");
  const url = formData.get("url");
  const commentId = formData.get("comment_id");

  // load the comment by id
  var commentResults = await context.env.COMMENTS.prepare(`SELECT * from comments where comment_id=?`).bind(commentId).all();

  if (commentResults.results.length == 0) {
    return new Response("Comment not found", { status: 404 });
  }

  // test that the comment was posted by the current user
  if (commentResults.results[0].user_id != context.data.decodedUser.userId) {
    return new Response("You can only edit your own comments", { status: 401 });
  }

  // test that the comment is less than 10 minutes old
  if (Date.now() - commentResults.results[0].timestamp > 600000) {
    return new Response("You can only edit comments for 10 minutes after posting", { status: 401 });
  }


  // now update the comment
  await context.env.COMMENTS.prepare(`UPDATE comments SET comment=?, sanitized_comment=? WHERE comment_id=?`).bind(comment, sanitizeHtml(marked.parse(comment)), commentId).run();




  // build a redirect url that will target the newly added comment, so it flashes with CSS
  const redirectUrl = new URL(formData.get("return_url") + "#scc-comment-" + commentId);
  var redirectResponse = Response.redirect(redirectUrl.toString(), 302);
  return redirectResponse;
}
