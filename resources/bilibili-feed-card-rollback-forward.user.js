// ==UserScript==
// @name         Bilibili Feed Card Rollback & Forward
// @name:zh-CN   Bilibili 推荐卡片回滚与前进
// @namespace    http://tampermonkey.net/
// @version      2.0-EdgeFix
// @description  Save and restore Bilibili feed card information, with rollback and forward functionality.
// @description:zh-CN 保存并恢复 B 站首页推荐卡片信息，提供 "回滚" 和 "前进" 功能，方便浏览。
// @author       Gemini 2.5 Pro (Based on GloryIsMine's script https://greasyfork.org/zh-CN/scripts/526397-bilibili-feed-card-rollback)
// @license      MIT
// @match        https://www.bilibili.com/*
// @grant        none
// ==/UserScript==

(function () {
    'use strict';

    const MAX_HISTORY = 20;
    const TIMELINE_KEY = 'bilibili_feed_timeline';
    const POINTER_KEY = 'bilibili_feed_pointer';
    const ROLLBACK_ID = 'bfrf-rollback-btn';
    const FORWARD_ID = 'bfrf-forward-btn';

    let lastStateSnapshot = null;
    let controlsCreated = false;
    let lastActionTime = 0;
    let isRestoring = false;

    function getFeedCardInfo() {
        const feedCards = document.querySelectorAll('.feed-card');
        if (feedCards.length === 0) return null;

        return Array.from(feedCards).map(card => {
            const picture = card.querySelector('.bili-video-card__cover');
            const avifSource = picture ? picture.querySelector('source[type="image/avif"]') : null;
            const webpSource = picture ? picture.querySelector('source[type="image/webp"]') : null;
            const imgSrc = picture ? picture.querySelector('img') : null;

            const linkElement = card.querySelector('.bili-video-card__info--tit a');
            const titleElement = card.querySelector('.bili-video-card__info--tit');
            const statsTexts = card.querySelectorAll('.bili-video-card__stats--text');
            const durationElement = card.querySelector('.bili-video-card__stats__duration');
            const authorElement = card.querySelector('.bili-video-card__info--author');

            return {
                coverInfo: {
                    avifSrcset: avifSource ? avifSource.srcset : '',
                    webpSrcset: webpSource ? webpSource.srcset : '',
                    imgSrc: imgSrc ? imgSrc.src : ''
                },
                title: titleElement ? titleElement.textContent.trim() : '',
                viewCount: statsTexts[0] ? statsTexts[0].textContent.trim() : '0',
                commentCount: statsTexts[1] ? statsTexts[1].textContent.trim() : '0',
                duration: durationElement ? durationElement.textContent.trim() : '',
                author: authorElement ? authorElement.textContent.trim() : '',
                videoUrl: linkElement ? linkElement.href : '',
            };
        });
    }

    function renderFeedCards(cardData) {
        const feedCards = document.querySelectorAll('.feed-card');
        if (feedCards.length === 0 || cardData.length === 0) return;

        const count = Math.min(feedCards.length, cardData.length);
        for (let index = 0; index < count; index++) {
            const card = feedCards[index];
            const info = cardData[index];
            if (!card || !info) continue;

            const picture = card.querySelector('.bili-video-card__cover');
            if (picture && info.coverInfo) {
                const avifSource = picture.querySelector('source[type="image/avif"]');
                const webpSource = picture.querySelector('source[type="image/webp"]');
                const img = picture.querySelector('img');

                if (avifSource && info.coverInfo.avifSrcset) avifSource.srcset = info.coverInfo.avifSrcset;
                if (webpSource && info.coverInfo.webpSrcset) webpSource.srcset = info.coverInfo.webpSrcset;
                if (img) {
                    if (info.coverInfo.imgSrc) img.src = info.coverInfo.imgSrc;
                    img.alt = info.title;
                }
            }
            const titleLinks = card.querySelectorAll('.bili-video-card__info--tit a');
            titleLinks.forEach(el => {
                el.textContent = info.title;
                el.href = info.videoUrl;
                el.title = info.title;
            });
            const stats = card.querySelectorAll('.bili-video-card__stats--text');
            if (stats[0]) stats[0].textContent = info.viewCount;
            if (stats[1]) stats[1].textContent = info.commentCount;
            const duration = card.querySelector('.bili-video-card__stats__duration');
            if (duration) duration.textContent = info.duration;
            const author = card.querySelector('.bili-video-card__info--author');
            if (author) author.textContent = info.author;
            const imageLink = card.querySelector('.bili-video-card__image--link');
            if (imageLink) imageLink.href = info.videoUrl;
        }
    }

    function saveNewState(newInfo) {
        if (!newInfo || newInfo.length === 0) return;

        let timeline = JSON.parse(sessionStorage.getItem(TIMELINE_KEY) || '[]');
        let pointer = parseInt(sessionStorage.getItem(POINTER_KEY) || '-1', 10);
        if (pointer < timeline.length - 1) {
            timeline = timeline.slice(0, pointer + 1);
        }
        timeline.push(newInfo);
        pointer++;
        if (timeline.length > MAX_HISTORY) {
            timeline.shift();
            pointer--;
        }
        sessionStorage.setItem(TIMELINE_KEY, JSON.stringify(timeline));
        sessionStorage.setItem(POINTER_KEY, pointer.toString());
        updateButtonStates();
    }

    function restoreState(newPointer) {
        let timeline = JSON.parse(sessionStorage.getItem(TIMELINE_KEY) || '[]');
        if (newPointer < 0 || newPointer >= timeline.length) return;

        isRestoring = true;
        const stateToRestore = timeline[newPointer];
        renderFeedCards(stateToRestore);
        sessionStorage.setItem(POINTER_KEY, newPointer.toString());
        lastStateSnapshot = JSON.stringify(getFeedCardInfo().map(c => c.videoUrl));
        updateButtonStates();
        setTimeout(() => { isRestoring = false; }, 500);
    }

    function handleRollback() {
        let pointer = parseInt(sessionStorage.getItem(POINTER_KEY) || '-1', 10);
        if (pointer <= 0) return;
        restoreState(pointer - 1);
    }

    function handleForward() {
        let timeline = JSON.parse(sessionStorage.getItem(TIMELINE_KEY) || '[]');
        let pointer = parseInt(sessionStorage.getItem(POINTER_KEY) || '-1', 10);
        if (pointer >= timeline.length - 1) return;
        restoreState(pointer + 1);
    }

    function updateButtonStates() {
        const rollbackBtn = document.getElementById(ROLLBACK_ID);
        const forwardBtn = document.getElementById(FORWARD_ID);
        if (!rollbackBtn || !forwardBtn) return;

        const timeline = JSON.parse(sessionStorage.getItem(TIMELINE_KEY) || '[]');
        const pointer = parseInt(sessionStorage.getItem(POINTER_KEY) || '-1', 10);

        const canRollback = pointer > 0;
        const canForward = pointer < timeline.length - 1;

        rollbackBtn.style.opacity = canRollback ? '1' : '0.4';
        rollbackBtn.style.cursor = canRollback ? 'pointer' : 'default';
        forwardBtn.style.opacity = canForward ? '1' : '0.4';
        forwardBtn.style.cursor = canForward ? 'pointer' : 'default';
    }

    function createControlButtons() {
        const feedRollBtn = document.querySelector('.feed-roll-btn');
        if (!feedRollBtn) return;

        controlsCreated = true;

        const container = document.createElement('div');
        container.id = 'bfrf-controls';
        container.style.cssText = 'position:fixed; display:flex; flex-direction:column; gap:8px; z-index:2147483647; pointer-events:auto;';

        const btnCss = 'display:block; padding:8px; background:#00a1d6; color:#fff; border:none; border-radius:4px; font-size:12px; width:54px; text-align:center; user-select:none; pointer-events:auto; cursor:pointer; transition:opacity .2s;';

        const rollbackBtn = document.createElement('div');
        rollbackBtn.id = ROLLBACK_ID;
        rollbackBtn.textContent = '回滚';
        rollbackBtn.style.cssText = btnCss;

        const forwardBtn = document.createElement('div');
        forwardBtn.id = FORWARD_ID;
        forwardBtn.textContent = '前进';
        forwardBtn.style.cssText = btnCss;

        container.appendChild(rollbackBtn);
        container.appendChild(forwardBtn);
        document.body.appendChild(container);

        function updatePosition() {
            const btn = document.querySelector('.feed-roll-btn');
            if (btn) {
                const rect = btn.getBoundingClientRect();
                container.style.left = rect.left + 'px';
                container.style.top = (rect.bottom + 8) + 'px';
                container.style.display = 'flex';
            } else {
                container.style.display = 'none';
            }
        }

        const posObserver = new ResizeObserver(updatePosition);
        posObserver.observe(document.body);
        posObserver.observe(feedRollBtn);
        window.addEventListener('scroll', updatePosition, true);
        updatePosition();
        updateButtonStates();
    }

    function setupGlobalClickCapture() {
        document.addEventListener('pointerdown', function (e) {
            const target = e.target;
            if (!target) return;

            let action = null;
            if (target.id === ROLLBACK_ID || target.closest('#' + ROLLBACK_ID)) {
                action = handleRollback;
            } else if (target.id === FORWARD_ID || target.closest('#' + FORWARD_ID)) {
                action = handleForward;
            }

            if (action) {
                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();

                const now = Date.now();
                if (now - lastActionTime < 300) return;
                lastActionTime = now;

                action();
            }
        }, true);
    }

    function initialize() {
        sessionStorage.removeItem(TIMELINE_KEY);
        sessionStorage.removeItem(POINTER_KEY);

        setupGlobalClickCapture();

        const initControlsInterval = setInterval(() => {
            if (document.querySelector('.feed-roll-btn') && !controlsCreated) {
                createControlButtons();
                clearInterval(initControlsInterval);
            }
        }, 500);

        const observer = new MutationObserver(() => {
            if (isRestoring) return;

            const currentCardsInfo = getFeedCardInfo();
            if (!currentCardsInfo) return;

            const currentSnapshot = JSON.stringify(currentCardsInfo.map(c => c.videoUrl));
            if (currentSnapshot !== lastStateSnapshot) {
                lastStateSnapshot = currentSnapshot;
                saveNewState(currentCardsInfo);
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    initialize();

})();

