#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
====qiqi-bot|status====
@Author：LoCCai
※Consult-List※
PurePeace -> SystemInfo
yanyongyu -> MessageSend
FengQi -> TimeTransform
※Consult-List※
"""
__author__ = "LoCCai"

from nonebot.matcher import Matcher
from nonebot.permission import SUPERUSER
from nonebot import on_notice, on_command, on_message

from .SystemInfo import get_status

status = on_command(
    "status",
    priority=10,
)

@status.handle()
async def status(matcher: Matcher):
    message=get_status()
    await Matcher.finish(message)