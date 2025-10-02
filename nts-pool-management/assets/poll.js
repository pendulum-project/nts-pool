// setup abort controller to clean up fetches when navigating to another page
const controller = new AbortController();
window.addEventListener("beforeunload", () => {
  controller.abort();
});

// long polling, when the server is up we get a 200 response every 30s
const longPoll = () => {
  fetch("/livereload/poll", {
    cache: "no-store",
    signal: controller.signal,
  })
    .catch(() => {
      if (!controller.signal.aborted) {
        console.log("[livereload] disconnected");
        shortPoll();
      }
    })
    .then((r) => {
      if (!controller.signal.aborted) {
        if (r && r.ok) {
          console.log("[livereload] heartbeat");
          longPoll();
        } else {
          console.log("[livereload] disconnected");
          shortPoll();
        }
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
      if (r && r.ok) {
        window.location.reload();
      } else {
        void setTimeout(shortPoll, 500);
      }
    })
    .catch(() => {
      void setTimeout(shortPoll, 500);
    });
};

// start with long polling when document is loaded
document.addEventListener("DOMContentLoaded", () => {
  longPoll();
  console.log("[livereload] running");
});
