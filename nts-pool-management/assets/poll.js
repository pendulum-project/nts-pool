// setup abort controller to clean up fetches when navigating to another page
const controller = new AbortController();
let shouldShortPoll = true;
window.addEventListener("beforeunload", () => {
  controller.abort();
  shouldShortPoll = false;
});

// long polling, when the server is up we get a 200 response every 30s
const longPoll = () => {
  fetch("/livereload/poll", { cache: "no-store", signal: controller.signal  })
    .catch(() => {
      if (shouldShortPoll) {
        console.log("[livereload] disconnected");
        shortPoll();
      }
    })
    .then((r) => {
      if (r.ok) {
        console.log("[livereload] heartbeat");
        longPoll();
      } else if (shouldShortPoll) {
        console.log("[livereload] disconnected");
        shortPoll();
      }
    });
};

// short polling, when the server is down we check it every 500ms
const shortPoll = () => {
  fetch("/livereload/healthy", {
    cache: "no-store",
    signal: AbortSignal.timeout(500),
  })
    .then((r) => {
      if (!r.ok) {
        void setTimeout(shortPoll, 500)
      } else {
        window.location.reload();
      }
    })
    .catch(() => {
      void setTimeout(shortPoll, 500)
    });
};

// start with long polling when document is loaded
document.addEventListener("DOMContentLoaded", () => {
  longPoll();
  console.log("[livereload] running");
});
